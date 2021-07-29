package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	pb "github.com/polarbroadband/gnmi/pkg/gnmiprobe"

	"github.com/polarbroadband/goto/util"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"

	log "github.com/sirupsen/logrus"
)

var (
	// container image release
	RELEASE = os.Getenv("RELEASE_PROBE")
	// container name
	HOST = os.Getenv("HOST_PROBE")
	// maximum number of concurrent sessions
	SESSION_MAX, _ = strconv.ParseInt(os.Getenv("SESSION_MAX"), 10, 64)
	// default session timeout 3 hr
	SESSION_TIMEOUT = 3 * 3600 * 1000000000
	// JWT shared secret
	TOKENSEC = []byte(os.Getenv("BACKEND_TOKEN"))

	// shared driver
	SHAREDRV = os.Getenv("HOST_SHAREDRV")

	// share driver file checking URL
	SDRV_CHK = "http://" + SHAREDRV + ":8060/latest"
	// share driver file download URL
	SDRV_DWL = "http://" + SHAREDRV + ":8061/share"

	// target certificate repo
	CACERT_LOCAL_REPO = "/certificate/"
	// ca certificate path
	CACERT_LOCAL_PATH = "ca/"
)

func init() {
	// config package level default logger
	log.SetFormatter(&log.JSONFormatter{})
	log.SetOutput(os.Stdout)
	log.SetLevel(log.TraceLevel)
}

type Nest struct {
	Probes map[string]*Probe
	nLock  *sync.Mutex
}

func (nest *Nest) DisconnectAll() {
	nest.nLock.Lock()
	for _, p := range nest.Probes {
		p.Target.Close()
	}
	nest.nLock.Unlock()
}

func (nest *Nest) RemoveProbe(id string) {
	nest.nLock.Lock()
	delete(nest.Probes, id)
	nest.nLock.Unlock()
}

func (nest *Nest) AddProbe(id string, r *Probe) {
	nest.nLock.Lock()
	defer nest.nLock.Unlock()
	nest.Probes[id] = r
}

func (nest *Nest) GetProbe(id string) *Probe {
	nest.nLock.Lock()
	defer nest.nLock.Unlock()
	return nest.Probes[id]
}

func (nest *Nest) Sessions() int64 {
	nest.nLock.Lock()
	defer nest.nLock.Unlock()
	return int64(len(nest.Probes))
}

type WorkerNode struct {
	pb.UnimplementedProbeServer
	*util.API
	//*util.MongoOpr
	*Nest
}

func main() {
	wkr := WorkerNode{
		Nest: &Nest{make(map[string]*Probe), &sync.Mutex{}},
		API: &util.API{
			TokenSec: TOKENSEC,
			NoAuth: []string{
				"/gnmiprobe.Probe/Healtz",
				"/gnmiprobe.Probe/ConnectProbe",
				"/gnmiprobe.Probe/Connect",
				"/gnmiprobe.Probe/Disconnect",
				"/gnmiprobe.Probe/Capability",
				"/gnmiprobe.Probe/Get",
				"/gnmiprobe.Probe/Set",
				"/gnmiprobe.Probe/Subscribe",
			},
			Log: log.WithField("owner", HOST),
		},
	}
	defer wkr.Nest.DisconnectAll()

	// setup and run gRPC server
	grpcListener, err := net.Listen("tcp", ":50051")
	if err != nil {
		wkr.Log.WithError(err).Fatal("gRPC server fail: unable to init tcp socket 50051")
	}
	// TLS
	grpcTLS, err := credentials.NewServerTLSFromFile("/appsrc/cert/gnmiprobe.cer", "/appsrc/cert/gnmiprobe_private.key")
	if err != nil {
		wkr.Log.WithError(err).Fatal("gRPC server fail: invalid TLS keys")
	}

	grpcSvr := grpc.NewServer(grpc.Creds(grpcTLS), grpc.UnaryInterceptor(wkr.AuthGrpcUnary), grpc.StreamInterceptor(wkr.AuthGrpcStream))

	// gRPC WorkerNode server
	pb.RegisterProbeServer(grpcSvr, &wkr)

	go func() {
		wkr.Log.Info("gRPC server start")
		wkr.Log.Fatal(grpcSvr.Serve(grpcListener))
	}()

	// config http server
	r := mux.NewRouter()
	rru := r.PathPrefix("").Subrouter()
	cors := handlers.CORS(
		handlers.AllowedOrigins([]string{`*`}),
		handlers.AllowedHeaders([]string{"content-type"}),
		handlers.AllowCredentials(),
		handlers.AllowedMethods([]string{"GET", "POST", "OPTIONS", "HEAD"}),
	)

	rru.HandleFunc("/healtz", wkr.healtz).Methods("GET")
	rru.HandleFunc("/ready", wkr.ready).Methods("GET")

	go func() {
		wkr.Log.Info("REST server start")
		wkr.Log.Fatal(http.ListenAndServe(":8060", cors(rru)))
	}()

	hold := make(chan struct{})
	<-hold
}

// healtz response k8s health check probe
func (wkr *WorkerNode) healtz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	_e := util.NewExeErr("healtz", HOST, "rest_API")
	if err := json.NewEncoder(w).Encode(map[string]string{"status": "done", "release": RELEASE}); err != nil {
		wkr.Error(w, 500, _e.String("erroneous api response", err))
	}
}

// ready response k8s readness check probe
func (wkr *WorkerNode) ready(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	_e := util.NewExeErr("ready", HOST, "rest_API")
	s := wkr.Sessions()
	if s > SESSION_MAX {
		wkr.Error(w, 503, fmt.Sprintf("%s overload, active sessions: %v, threshold: %v", HOST, s, SESSION_MAX))
	} else if err := json.NewEncoder(w).Encode(map[string]interface{}{"status": "done", "sessions": s}); err != nil {
		wkr.Error(w, 500, _e.String("erroneous api response", err))
	}
}

// Healtz response gRPC health check
func (wkr *WorkerNode) Healtz(ctx context.Context, r *pb.HealtzReq) (*pb.SvrStat, error) {
	//_e := util.NewExeErr("Healtz", HOST, "gRPC_API")
	return &pb.SvrStat{
		Host:    HOST,
		Release: RELEASE,
		Load:    wkr.Sessions(),
	}, nil
}

func (wkr *WorkerNode) ConnectProbe(stream pb.Probe_ConnectProbeServer) error {
	_e := util.NewExeErr("ConnectProbe", HOST, "gNMI Probe")
	pid := util.RandString(10)
	abort := make(chan error, 2)
	reqCh := make(chan *pb.ProbeRequest)
	aggCh := make(chan *pb.ProbeResponse, 5)
	defer func() {
		time.Sleep(time.Second * 3)
		close(aggCh)
		wkr.RemoveProbe(pid)
	}()

	// launch command input stream loop
	go func() {
		for {
			in, err := stream.Recv()
			if err == io.EOF {
				// gNMI Probe stream closed by caller
				close(reqCh)
				return
			}
			if err != nil {
				select {
				case <-abort:
				default:
					abort <- fmt.Errorf("session %v inbound stream error: %v", pid, err)
				}
				return
			}
			reqCh <- in
		}
	}()

	// launch aggregated output stream loop
	go func() {
		for data := range aggCh {
			if err := stream.Send(data); err != nil {
				select {
				case <-abort:
				default:
					abort <- fmt.Errorf("session %v outbound stream error: %v", pid, err)
				}
				return
			}
		}
	}()

	// wait for ProbeConn request
	leadTimer := time.NewTimer(time.Second * 3)
	var req *pb.ProbeRequest
	select {
	case <-leadTimer.C:
		return wkr.Errpc(codes.FailedPrecondition, _e.String("session timeout before receiving ProbeConn request"))
	case req = <-reqCh:
		if req == nil {
			return wkr.Errpc(codes.FailedPrecondition, _e.String("session closed by caller before receiving ProbeConn request"))
		}
	}
	// establish target connection
	sc := req.GetConn()
	if sc == nil {
		return wkr.Errpc(codes.FailedPrecondition, _e.String("missing ProbeConn request"))
	}
	url := sc.GetHost() + ":" + sc.GetPort()
	conn, err := ConnTarget(stream.Context(), sc)
	if err != nil {
		return wkr.Errpc(codes.Unavailable, _e.String("unable to connect target "+url, err))
	}
	defer conn.Close()

	log.Infof("target %s connected, transport state: %v", url, conn.GetState())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	probe := Probe{
		ProbeConn: sc,
		Handle:    gnmipb.NewGNMIClient(conn),
		Out:       &aggCh,
		Start:     time.Now().UTC(),
		Ctx:       metadata.AppendToOutgoingContext(ctx, "username", sc.GetUsr(), "password", sc.GetPwd()),
		Streams:   make(map[int64]context.CancelFunc),
		sLock:     &sync.Mutex{},
	}
	// update nest
	wkr.AddProbe(pid, &probe)
	// update session timer
	sessionTimer := time.NewTimer(time.Duration(SESSION_TIMEOUT))
	if tt := req.GetTimeout(); tt > 0 {
		sessionTimer = time.NewTimer(time.Duration(tt * 1000000000))
	}
	// ack connection request
	aggCh <- &pb.ProbeResponse{Cid: req.GetCid(), Error: ""}

	// exec
	for {
		select {
		case req := <-reqCh:
			if req == nil {
				log.Infof("session %v inbound stream closed by caller", pid)
				return nil
			}

			if sc := req.GetGet(); sc != nil {
				// get data from target
				go probe.Get(sc, req.GetCid(), req.GetTimeout())
			} else if sc := req.GetSet(); sc != nil {
				// set target field
				go probe.Set(sc, req.GetCid(), req.GetTimeout())
			} else if sc := req.GetSub(); sc != nil {
				// subscribe data stream
				if cancel := probe.GetStreamHandle(req.GetCid()); cancel != nil {
					// cancel existiing subscription
					log.Infof("session %v subscription %v cancelled by caller", pid, req.GetCid())
					cancel()
				} else {
					go probe.Sub(sc, req.GetCid(), req.GetTimeout())
				}
			} else {
				// invalid opr
				return wkr.Errpc(codes.Unavailable, _e.String("invalid gNMI Probe operation"))
			}
		case err := <-abort:
			return wkr.Errpc(codes.Aborted, _e.String("abort", err))
		case <-sessionTimer.C:
			return wkr.Errpc(codes.DeadlineExceeded, _e.String("session "+pid+" timeout"))
		}
	}
}

// Connect set up target connection and initialize Probe instance
func (wkr *WorkerNode) Connect(ctx context.Context, r *pb.ProbeConn) (*pb.ProbeBase, error) {
	targetAddr := r.GetHost() + ":" + r.GetPort()
	_e := util.NewExeErr("Connect", HOST, "gNMI_target_"+targetAddr)
	p, _ := peer.FromContext(ctx)
	conn, err := ConnTarget(ctx, r)
	if err != nil {
		return nil, wkr.Errpc(codes.Unavailable, _e.String(fmt.Sprintf(" gNMI Probe %s unable to connect target %s for client %s", HOST, targetAddr, p.Addr.String()), err))
	}
	// init Probe instance
	probe := Probe{
		ProbeConn:  r,
		ClientAddr: p.Addr.String(),
		Target:     conn,
		Handle:     gnmipb.NewGNMIClient(conn),
		Start:      time.Now().UTC(),
	}
	pid := util.RandString(10)
	wkr.AddProbe(pid, &probe)
	log.Infof("Probe %s init, target %s connected, transport state: %v", pid, targetAddr, conn.GetState())

	return &pb.ProbeBase{ID: pid}, nil
}

// Disconnect close target connection and remove Probe instance
func (wkr *WorkerNode) Disconnect(ctx context.Context, r *pb.ProbeBase) (*pb.OprStat, error) {
	//_e := util.NewExeErr("Disonnect", HOST, "gRPC_API")
	probe := wkr.GetProbe(r.GetID())
	if probe != nil {
		probe.Target.Close()
		wkr.RemoveProbe(r.GetID())
		log.Infof("target %s:%s disconnected, probe %s closed", probe.GetHost(), probe.GetPort(), r.GetID())
		return &pb.OprStat{Status: "done"}, nil
	}
	return &pb.OprStat{Status: "nonexist"}, nil
}

// Capability implement target Capability
func (wkr *WorkerNode) Capability(channelCtx context.Context, r *pb.ProbeBase) (*gnmipb.CapabilityResponse, error) {
	_e := util.NewExeErr("Capability", HOST, r.GetID())
	probe := wkr.GetProbe(r.GetID())
	if probe == nil {
		return nil, wkr.Errpc(codes.InvalidArgument, _e.String("not exist"))
	}

	ctx, cancel := context.WithTimeout(channelCtx, time.Second*10) // default gNMI Capability timeout 10s
	defer cancel()

	result, err := probe.Handle.Capabilities(probe.Auth(ctx), &gnmipb.CapabilityRequest{})
	if err != nil {
		err = wkr.Errpc(codes.Unavailable, _e.String(probe.Host+":"+probe.Port, err))
	}
	return result, err
}

// Get implement target GET
func (wkr *WorkerNode) Get(channelCtx context.Context, r *pb.GetRequest) (*gnmipb.GetResponse, error) {
	_e := util.NewExeErr("Get", HOST, r.GetID())
	probe := wkr.GetProbe(r.GetID())
	if probe == nil {
		return nil, wkr.Errpc(codes.InvalidArgument, _e.String("not exist"))
	}

	ctx, cancel := context.WithTimeout(channelCtx, time.Second*900) // default gNMI GET timeout 900s
	defer cancel()

	result, err := probe.Handle.Get(probe.Auth(ctx), r.GetRequest())
	if err != nil {
		err = wkr.Errpc(codes.Unavailable, _e.String(probe.Host+":"+probe.Port, err))
	}
	return result, err
}

// Set implement target SET
func (wkr *WorkerNode) Set(channelCtx context.Context, r *pb.SetRequest) (*gnmipb.SetResponse, error) {
	_e := util.NewExeErr("Set", HOST, r.GetID())
	probe := wkr.GetProbe(r.GetID())
	if probe == nil {
		return nil, wkr.Errpc(codes.InvalidArgument, _e.String("not exist"))
	}

	ctx, cancel := context.WithTimeout(channelCtx, time.Second*10) // default gNMI SET timeout 10s
	defer cancel()

	result, err := probe.Handle.Set(probe.Auth(ctx), r.GetRequest())
	if err != nil {
		err = wkr.Errpc(codes.Unavailable, _e.String(probe.Host+":"+probe.Port, err))
	}
	return result, err
}

// Subscribe implement target Subscribe
func (wkr *WorkerNode) Subscribe(r *pb.SubscribeRequest, stream pb.Probe_SubscribeServer) error {
	_e := util.NewExeErr("Subscribe", HOST, r.GetID())
	probe := wkr.GetProbe(r.GetID())
	if probe == nil {
		return wkr.Errpc(codes.InvalidArgument, _e.String("not exist"))
	}

	ctx, cancel := context.WithTimeout(stream.Context(), time.Hour*2400) // default gNMI Subscribe timeout 100 day
	defer cancel()

	subHdl, err := probe.Handle.Subscribe(probe.Auth(ctx))
	if err != nil {
		return wkr.Errpc(codes.Unavailable, _e.String(probe.Host+":"+probe.Port, err))
	}
	if err := subHdl.Send(r.GetRequest()); err != nil {
		return wkr.Errpc(codes.Unavailable, _e.String(probe.Host+":"+probe.Port, err))
	}

	for {
		res, err := subHdl.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return wkr.Errpc(codes.Unavailable, _e.String(probe.Host+":"+probe.Port, err))
		}
		switch res.Response.(type) {
		case *gnmipb.SubscribeResponse_SyncResponse:
			//log.Info("SyncResponse received")
		case *gnmipb.SubscribeResponse_Update:
			if err := stream.Send(res); err != nil {
				return wkr.Errpc(codes.Unavailable, _e.String(fmt.Sprintf("unable to forward %s:%s subscription to client %s", probe.Host, probe.Port, probe.ClientAddr), err))
			}
		default:
			return wkr.Errpc(codes.Unavailable, _e.String(probe.Host+":"+probe.Port, "unexpected stream response type"))
		}
	}
}

type Probe struct {
	// target parameters
	*pb.ProbeConn
	// client address
	ClientAddr string
	// target connection
	Target *grpc.ClientConn
	// target connection handle
	Handle gnmipb.GNMIClient

	// client bound stream outlet
	Out *chan *pb.ProbeResponse
	// session start time
	Start   time.Time
	Ctx     context.Context
	Streams map[int64]context.CancelFunc
	sLock   *sync.Mutex
}

func (p *Probe) Auth(ctx context.Context) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "username", p.GetUsr(), "password", p.GetPwd())
}

func (p *Probe) GetStreamHandle(cid int64) context.CancelFunc {
	p.sLock.Lock()
	defer p.sLock.Unlock()
	return p.Streams[cid]
}

func (p *Probe) AddStreamHandle(cid int64, f context.CancelFunc) {
	p.sLock.Lock()
	defer p.sLock.Unlock()
	p.Streams[cid] = f
}

func (p *Probe) RmvStreamHandle(cid int64) {
	p.sLock.Lock()
	defer p.sLock.Unlock()
	delete(p.Streams, cid)
}

func (p *Probe) Get(req *gnmipb.GetRequest, cid, tt int64) {
	if tt <= 0 {
		tt = 5
	}
	ctx, cancel := context.WithTimeout(p.Ctx, time.Duration(tt*1000000000))
	defer cancel()
	response := pb.ProbeResponse{Cid: cid}
	if result, err := p.Handle.Get(ctx, req); err != nil {
		response.Error = fmt.Sprintf("failed target GET: %v", err)
	} else {
		response.Resp = result.GetNotification()
	}

	*p.Out <- &response
}

func (p *Probe) Set(req *gnmipb.SetRequest, cid, tt int64) {
	if tt <= 0 {
		tt = 5
	}
	ctx, cancel := context.WithTimeout(p.Ctx, time.Duration(tt*1000000000))
	defer cancel()

	response := pb.ProbeResponse{Cid: cid}
	if _, err := p.Handle.Set(ctx, req); err != nil {
		response.Error = fmt.Sprintf("failed target SET: %v", err)
	}

	*p.Out <- &response
}

func (p *Probe) Sub(req *gnmipb.SubscribeRequest, cid, tt int64) {
	if tt <= 0 {
		tt = 3 * 3600
	}
	ctx, cancel := context.WithTimeout(p.Ctx, time.Duration(tt*1000000000))
	p.AddStreamHandle(cid, cancel)
	defer func() {
		cancel()
		p.RmvStreamHandle(cid)
	}()
	response := pb.ProbeResponse{Cid: cid}
	subHdl, err := p.Handle.Subscribe(ctx)
	if err != nil {
		response.Error = fmt.Sprintf("unable create GNMI_SubscribeClient: %v", err)
		*p.Out <- &response
		return
	}
	if err := subHdl.Send(req); err != nil {
		response.Error = fmt.Sprintf("failed target stream request: %v", err)
		*p.Out <- &response
		return
	}
	for {
		res, err := subHdl.Recv()
		if err == io.EOF {
			*p.Out <- &response
			return
		}
		if err != nil {
			response.Error = fmt.Sprintf("target streaming error: %v", err)
			*p.Out <- &response
			return
		}
		switch res.Response.(type) {
		case *gnmipb.SubscribeResponse_SyncResponse:
			//log.Info("SyncResponse received")
		case *gnmipb.SubscribeResponse_Update:
			response.Resp = []*gnmipb.Notification{res.GetUpdate()}
			*p.Out <- &response
		default:
			response.Error = "unexpected stream response type"
			*p.Out <- &response
			return
		}
	}
}

func ConnTarget(cctx context.Context, cfg *pb.ProbeConn) (*grpc.ClientConn, error) {
	url := cfg.GetHost() + ":" + cfg.GetPort()
	ctx, cancel := context.WithTimeout(cctx, time.Duration(time.Second*10)) // default connection pending timeout 10s
	defer cancel()

	if cfg.GetTLS() {
		if caCert := cfg.GetCer(); caCert == "" {
			// TLS trust, skip certificate verification
			return grpc.DialContext(
				ctx,
				url,
				grpc.WithBlock(),
				grpc.WithReturnConnectionError(),
				grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: true})),
			)
		} else {
			// TLS, vertify target with preload ca certificate
			if err := GetShareFile(SDRV_CHK, SDRV_DWL, CACERT_LOCAL_REPO, CACERT_LOCAL_PATH, cfg.GetCer()); err != nil {
				return nil, fmt.Errorf("missing CA certificate file: %v", err)
			}
			caCert, err := credentials.NewClientTLSFromFile(cfg.GetCer(), "")
			if err != nil {
				return nil, fmt.Errorf("unable to import CA certificate: %v", err)
			}
			return grpc.DialContext(
				ctx,
				url,
				grpc.WithBlock(),
				grpc.WithReturnConnectionError(),
				grpc.WithTransportCredentials(caCert),
			)
		}
	}
	// no TLS
	return grpc.DialContext(
		ctx,
		url,
		grpc.WithBlock(),
		grpc.WithReturnConnectionError(),
		grpc.WithInsecure(),
	)
}

/*
GetShareFile load file from share drive if not local exist
apiChk: sdrv File version check api i.e "http://" + SHAREDRV + ":8060/latest"
apiDwl: sdrv File download api i.e "http://" + SHAREDRV + ":8061/share"
repo: local file directory, must start from root "/" and tailing with "/" i.e /cer/
path: file path, no leading "/", must have a tailing "/" if not empty i.e ca/cer/ or empty
file: file name i.e public.cert

file must have the same path/name on server and local repo
*/
func GetShareFile(apiChk, apiDwl, repo, path, file string) error {
	if _, exist, chksum := util.FileExist(repo+path+file, ""); exist {
		// verify file is the latest version
		request, _ := json.Marshal(map[string]string{
			"name":   path + file,
			"chksum": chksum,
		})
		resp, err := http.Post(apiChk, "application/json", bytes.NewBuffer(request))
		if err != nil {
			return fmt.Errorf("unable to check file on share drive: %v", err)
		}
		defer resp.Body.Close()

		rb := make(map[string]interface{})
		json.NewDecoder(resp.Body).Decode(&rb)
		if resp.StatusCode >= 300 {
			return fmt.Errorf("server internal error: %s, reponse body: %+v", resp.Status, rb)
		}
		exist, ok := rb["exist"].(bool)
		sdErr, okk := rb["errors"].(string)
		if !ok || !okk {
			return fmt.Errorf("server internal error: invalid response body: %+v", rb)
		}
		if !exist {
			return fmt.Errorf("file not found on the share drive: %s", sdErr)
		}
		if sdErr == "" {
			// local repo has the latest file
			return nil
		}
	}
	// load the latest file from shared drive
	resp, err := http.Get(apiDwl + "/" + path + file)
	if err != nil {
		return fmt.Errorf("server internal error: %v", err)
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("unable to get file from share drive: %s", resp.Status)
	}
	defer resp.Body.Close()
	out, err := os.Create(repo + path + file)
	if err != nil {
		return fmt.Errorf("unable to create file on container: %v", err)
	}
	defer out.Close()

	if _, err := io.Copy(out, resp.Body); err != nil {
		return fmt.Errorf("unable to save file on container: %v", err)
	}
	return nil
}
