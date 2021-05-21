package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	pb "gitlab01.nfvdev.teluslabs.net/t854359/protobuf/gnmiprobe"
	runnerpb "gitlab01.nfvdev.teluslabs.net/t854359/protobuf/runner"

	"github.com/google/gnxi/utils/xpath"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/kr/pretty"
	log "github.com/sirupsen/logrus"
)

var (
	ENCODING = "JSON"

	// container image release
	RELEASE = os.Getenv("RELEASE_CLNT")
	// container name
	HOST  = os.Getenv("HOST_CLNT")
	PROBE = os.Getenv("HOST_PROBE")
	// JWT shared secret
	TOKENSEC = []byte(os.Getenv("BACKEND_TOKEN"))
)

func init() {
	// config package level default logger
	log.SetFormatter(&log.JSONFormatter{})
	log.SetOutput(os.Stdout)
	log.SetLevel(log.TraceLevel)
}

func main() {

	if res, err := http.Get("http://" + PROBE + ":8060/healtz"); err != nil {
		log.Fatalf("%s healtz check fail: %v", PROBE, err)
	} else {
		var rb map[string]interface{}
		json.NewDecoder(res.Body).Decode(&rb)
		res.Body.Close()
		pretty.Printf("\n*** probe healtz check ***\n%# v\n", rb)
	}

	if res, err := http.Get("http://" + PROBE + ":8060/ready"); err != nil {
		log.Fatalf("%s load check fail: %v", PROBE, err)
	} else {
		var rb map[string]interface{}
		json.NewDecoder(res.Body).Decode(&rb)
		res.Body.Close()
		pretty.Printf("\n*** probe load check ***\n%# v\n", rb)
	}

	caCer, err := credentials.NewClientTLSFromFile("/appsrc/cert/ca.cert", "")
	if err != nil {
		log.Fatalf("unable to import ca certificate: %v", err)
	}
	// Set up TLS connection to the server
	probeConn, err := grpc.Dial(PROBE+":50051", grpc.WithTransportCredentials(caCer))
	if err != nil {
		log.Fatal("unable to connect %s: %v", PROBE, err)
	}
	defer probeConn.Close()
	probe := pb.NewProbeClient(probeConn)
	gCtx, gCancel := context.WithCancel(context.Background())
	defer gCancel()
	if res, err := probe.Healtz(gCtx, &runnerpb.HealtzReq{}); err != nil {
		log.Fatalf("%s gRPC healtz check fail: %v", PROBE, err)
	} else {
		fmt.Printf("\n*** probe gRPC healtz check ***\nHost: %s\nRel: %s\nLoad: %v\n", res.GetHost(), res.GetRelease(), res.GetLoad())
	}

	psm := GNMI{
		Ctx:         gCtx,
		Cancel:      gCancel,
		ProbeClient: probe,
		Ready:       false,
		rLock:       &sync.Mutex{},
		Callers:     make(map[int64]*chan *ResponseGNMI),
		CallersCt:   0,
		cLock:       &sync.Mutex{},

		Config: &pb.ProbeConn{
			TLS:  false,
			Cer:  "",
			Host: "172.25.208.195",
			Port: "57400",
			Usr:  "gnmi",
			Pwd:  "telus123",
		},
	}
	defer psm.Close()

	secP, _ := xpath.ToGNMIPath("/configure/port[port-id=1/1/c11/1]")
	resp, err := psm.Get([]*gnmipb.Path{secP})
	if err != nil {
		log.Fatal(err)
	}
	for _, notification := range resp {
		for _, update := range notification.GetUpdate() {
			var res map[string]interface{}
			json.Unmarshal(update.GetVal().GetJsonVal(), &res)
			//pretty.Printf("\nGetResponse *****************%v\n%# v\n", notification.GetPrefix(), res)
			fmt.Printf("\n++ 1 ++\nport %s %s\n\n", res["port-id"], res["description"])
		}
	}

	cc := make(chan struct{})
	go func() {
		secP, _ := xpath.ToGNMIPath("/state/port[port-id=1/1/c11/1]/statistics/in-packets")
		subscriptions := []*gnmipb.Subscription{
			{
				Path:           secP,
				Mode:           gnmipb.SubscriptionMode_SAMPLE, // pb.SubscriptionMode_ON_CHANGE, pb.SubscriptionMode_TARGET_DEFINED
				SampleInterval: 1000000000,                     // ns, unit64
				//SuppressRedundant: true,
				//HeartbeatInterval: 30000000000, // ns, unit64
			},
		}
		cd := make(chan *ResponseGNMI)
		go psm.Sub(&cc, &cd, subscriptions, 5)

		for res := range cd {
			if res.Error != "" {
				log.Info(res.Error)
				return
			}

			for _, notification := range res.Resp {
				for _, update := range notification.GetUpdate() {
					var ct interface{}
					json.Unmarshal(update.GetVal().GetJsonVal(), &ct) // string
					fmt.Printf("-- %v %v %v\n", notification.GetPrefix(), notification.GetTimestamp(), ct)
				}

			}
		}
	}()

	time.Sleep(time.Second * 3)

	secP, _ = xpath.ToGNMIPath("/configure/port[port-id=1/1/c10/1]")
	resp, err = psm.Get([]*gnmipb.Path{secP})
	if err != nil {
		log.Fatal(err)
	}
	for _, notification := range resp {
		for _, update := range notification.GetUpdate() {
			var res map[string]interface{}
			json.Unmarshal(update.GetVal().GetJsonVal(), &res)
			//pretty.Printf("\nGetResponse *****************%v\n%# v\n", notification.GetPrefix(), res)
			fmt.Printf("\n++ 2 ++\nport %s %s\n\n", res["port-id"], res["description"])
		}
	}

	time.Sleep(time.Second * 3)

	go func() {
		secP, _ := xpath.ToGNMIPath("/state/port[port-id=1/1/c11/1]/statistics/in-packets")
		subscriptions := []*gnmipb.Subscription{
			{
				Path:           secP,
				Mode:           gnmipb.SubscriptionMode_SAMPLE, // pb.SubscriptionMode_ON_CHANGE, pb.SubscriptionMode_TARGET_DEFINED
				SampleInterval: 1000000000,                     // ns, unit64
				//SuppressRedundant: true,
				//HeartbeatInterval: 30000000000, // ns, unit64
			},
		}
		cd := make(chan *ResponseGNMI)
		go psm.Sub(&cc, &cd, subscriptions, 5)

		for res := range cd {
			if res.Error != "" {
				log.Info(res.Error)
				return
			}

			for _, notification := range res.Resp {
				for _, update := range notification.GetUpdate() {
					var ct interface{}
					json.Unmarshal(update.GetVal().GetJsonVal(), &ct) // string
					fmt.Printf("-- %v %v %v\n", notification.GetPrefix(), notification.GetTimestamp(), ct)
				}

			}
		}
	}()

	time.Sleep(time.Second * 3)
	close(cc)
	fmt.Println("+++++++subscription cancelled, client")

	time.Sleep(time.Second * 1)
	secP, _ = xpath.ToGNMIPath("/configure/port[port-id=1/1/c10/1]")
	resp, err = psm.Get([]*gnmipb.Path{secP})
	if err != nil {
		log.Info(err)
	}
	for _, notification := range resp {
		for _, update := range notification.GetUpdate() {
			var res map[string]interface{}
			json.Unmarshal(update.GetVal().GetJsonVal(), &res)
			//pretty.Printf("\nGetResponse *****************%v\n%# v\n", notification.GetPrefix(), res)
			fmt.Printf("\n++ 3 ++\nport %s %s\n\n", res["port-id"], res["description"])
		}
	}

	hold := make(chan struct{})
	<-hold
}

type ResponseGNMI struct {
	Resp  []*gnmipb.Notification
	Error string
}

type GNMI struct {
	Ctx    context.Context
	Cancel context.CancelFunc
	pb.ProbeClient
	//pb.Probe_ConnectProbeClient
	Ready bool
	rLock *sync.Mutex

	Callers   map[int64]*chan *ResponseGNMI
	CallersCt int64
	cLock     *sync.Mutex

	ToProbe *chan *pb.ProbeRequest

	Config *pb.ProbeConn
}

func (p *GNMI) SetCaller() int64 {
	respCh := make(chan *ResponseGNMI)
	p.cLock.Lock()
	p.CallersCt++
	cid := p.CallersCt
	p.Callers[cid] = &respCh
	p.cLock.Unlock()
	return cid
}

func (p *GNMI) ClearCaller(cid int64) {
	p.cLock.Lock()
	delete(p.Callers, cid)
	p.cLock.Unlock()
}

func (p *GNMI) AlertCallers(err interface{}) {
	for _, c := range p.Callers {
		*c <- &ResponseGNMI{Error: fmt.Sprint(err)}
	}
}

func (p *GNMI) CloseCallers() {
	p.cLock.Lock()
	for _, c := range p.Callers {
		close(*c)
	}
	p.cLock.Unlock()
}

func (p *GNMI) Close() {
	p.rLock.Lock()
	p.Ready = false
	close(*p.ToProbe)
	p.Cancel()
	p.rLock.Unlock()
}

func (p *GNMI) Conn() error {
	p.rLock.Lock()
	defer p.rLock.Unlock()
	if !p.Ready {
		// init probe stream and connect to target
		stream, err := p.ConnectProbe(p.Ctx)
		if err != nil {
			return fmt.Errorf("unable to connect probe: %v", err)
		}
		connID := p.SetCaller()

		go func() {
			defer func() {
				// close all caller channels
				p.CloseCallers()
				// close probe
				p.Close()
				log.Info("receiver loop closed")
			}()

			for {
				rsp, err := stream.Recv()
				if err == io.EOF {
					log.Info("probe session disconnected")
					return
				}
				if err != nil {
					// probe stream, alert all callers and abort
					log.Infof("probe session disconnected due to error: %v", err)
					p.AlertCallers(err)
					return
				}
				// dispatch, error handled by caller
				if toCaller, exist := p.Callers[rsp.GetCid()]; !exist {
					// inconsist caller id, alert all callers and abort
					p.AlertCallers(fmt.Sprintf("caller %v not exist", rsp.GetCid()))
					return
				} else {
					*toCaller <- &ResponseGNMI{Resp: rsp.GetResp(), Error: rsp.Error}
				}
			}
		}()

		if err := stream.Send(&pb.ProbeRequest{
			Cid:     connID,
			Timeout: 24 * 3600,
			Request: &pb.ProbeRequest_Conn{Conn: p.Config},
		}); err != nil {
			return fmt.Errorf("unable to init probe: %v", err)
		}

		// wait for probe init ack
		oprTimeout := time.NewTimer(time.Second * 10)
		select {
		case <-p.Ctx.Done():
			return fmt.Errorf("gnmi closed before init")
		case <-oprTimeout.C:
			return fmt.Errorf("probe init ack timeout")
		case req := <-*p.Callers[connID]:
			if req == nil {
				return fmt.Errorf("probe stream closed before init")
			}
			if req.Error != "" {
				return fmt.Errorf("unable to init probe: %v", req.Error)
			}
		}

		// launch sender loop
		out := make(chan *pb.ProbeRequest)
		p.ToProbe = &out
		go func() {
			defer log.Info("sender loop closed")
			for opr := range out {
				if err := stream.Send(opr); err != nil {
					// probe stream error handled by caller
					*p.Callers[opr.GetCid()] <- &ResponseGNMI{Error: fmt.Sprintf("fail to send request: %v", err)}
				}
			}
		}()

		log.Info("probe ready")
		p.Ready = true
	}

	return nil
}

// Get to get models specified by given path list
func (p *GNMI) Get(pathList []*gnmipb.Path) ([]*gnmipb.Notification, error) {
	if err := p.Conn(); err != nil {
		return nil, err
	}

	cid := p.SetCaller()
	defer p.ClearCaller(cid)

	encoding, _ := gnmipb.Encoding_value[ENCODING]
	pbModelDataList := []*gnmipb.ModelData{}
	getRequest := &gnmipb.GetRequest{
		Encoding:  gnmipb.Encoding(encoding),
		Path:      pathList,
		UseModels: pbModelDataList,
	}

	oprTimeout := time.NewTimer(time.Second * 10)
	select {
	case <-p.Ctx.Done():
		return nil, fmt.Errorf("gnmi GET request not sent, gnmi closed")
	case <-oprTimeout.C:
		return nil, fmt.Errorf("gnmi GET timeout on request")
	case *p.ToProbe <- &pb.ProbeRequest{
		Cid:     cid,
		Timeout: 5,
		Request: &pb.ProbeRequest_Get{Get: getRequest},
	}:
	}

	select {
	case <-p.Ctx.Done():
		return nil, fmt.Errorf("gnmi GET failed, gnmi closed")
	case <-oprTimeout.C:
		return nil, fmt.Errorf("gnmi GET timeout on response")
	case res := <-*p.Callers[cid]:
		if res == nil {
			return nil, fmt.Errorf("gnmi GET failed, probe stream closed")
		}
		if res.Error != "" {
			return nil, fmt.Errorf("gnmi GET failed: %v", res.Error)
		}
		return res.Resp, nil
	}
}

// Update to update the target model fields by gNMI SET
// only accept key/value pairs
func (p *GNMI) Update(path *gnmipb.Path, val map[string]interface{}) error {
	if err := p.Conn(); err != nil {
		return err
	}

	cid := p.SetCaller()
	defer p.ClearCaller(cid)

	toUpdate, err := json.Marshal(val)
	if err != nil {
		return fmt.Errorf("unable to assemble the update value: %v", err)
	}
	setRequest := &gnmipb.SetRequest{
		Delete:  nil, //[]*pb.Path
		Replace: nil, //[]*pb.Update
		Update: []*gnmipb.Update{{
			Path: path,
			Val: &gnmipb.TypedValue{
				//Value: &pb.TypedValue_StringVal{StringVal: VALUE_UPDATE},
				Value: &gnmipb.TypedValue_JsonVal{JsonVal: toUpdate},
			},
		}},
	}

	oprTimeout := time.NewTimer(time.Second * 10)
	select {
	case <-p.Ctx.Done():
		return fmt.Errorf("gnmi closed before SET request sent to Probe")
	case <-oprTimeout.C:
		return fmt.Errorf("gnmi SET timeout on request")
	case *p.ToProbe <- &pb.ProbeRequest{
		Cid:     cid,
		Timeout: 5,
		Request: &pb.ProbeRequest_Set{Set: setRequest},
	}:
	}

	select {
	case <-p.Ctx.Done():
		return fmt.Errorf("gnmi SET failed, gnmi closed")
	case <-oprTimeout.C:
		return fmt.Errorf("gnmi SET timeout on response")
	case res := <-*p.Callers[cid]:
		if res == nil {
			return fmt.Errorf("gnmi SET failed, probe stream closed")
		}
		if res.Error != "" {
			return fmt.Errorf("gnmi SET failed: %v", res.Error)
		}
		return nil
	}
}

// Replace to replace the target model fields by gNMI SET
// only accept key/value pairs
func (p *GNMI) Replace(path *gnmipb.Path, val map[string]interface{}) error {
	if err := p.Conn(); err != nil {
		return err
	}

	cid := p.SetCaller()
	defer p.ClearCaller(cid)

	toUpdate, err := json.Marshal(val)
	if err != nil {
		return fmt.Errorf("unable to assemble the update value: %v", err)
	}
	setRequest := &gnmipb.SetRequest{
		Replace: []*gnmipb.Update{{
			Path: path,
			Val: &gnmipb.TypedValue{
				Value: &gnmipb.TypedValue_JsonVal{JsonVal: toUpdate},
			},
		}},
	}

	oprTimeout := time.NewTimer(time.Second * 10)
	select {
	case <-p.Ctx.Done():
		return fmt.Errorf("gnmi closed before SET request sent to Probe")
	case <-oprTimeout.C:
		return fmt.Errorf("gnmi SET timeout on request")
	case *p.ToProbe <- &pb.ProbeRequest{
		Cid:     cid,
		Timeout: 5,
		Request: &pb.ProbeRequest_Set{Set: setRequest},
	}:
	}

	select {
	case <-p.Ctx.Done():
		return fmt.Errorf("gnmi SET failed, gnmi closed")
	case <-oprTimeout.C:
		return fmt.Errorf("gnmi SET timeout on response")
	case res := <-*p.Callers[cid]:
		if res == nil {
			return fmt.Errorf("gnmi SET failed, probe stream closed")
		}
		if res.Error != "" {
			return fmt.Errorf("gnmi SET failed: %v", res.Error)
		}
		return nil
	}
}

// Delete to delete the target model fields by gNMI SET
func (p *GNMI) Delete(pathList []*gnmipb.Path) error {
	if err := p.Conn(); err != nil {
		return err
	}

	cid := p.SetCaller()
	defer p.ClearCaller(cid)

	setRequest := &gnmipb.SetRequest{
		Delete: pathList,
	}

	oprTimeout := time.NewTimer(time.Second * 10)
	select {
	case <-p.Ctx.Done():
		return fmt.Errorf("gnmi closed before SET request sent to Probe")
	case <-oprTimeout.C:
		return fmt.Errorf("gnmi SET timeout on request")
	case *p.ToProbe <- &pb.ProbeRequest{
		Cid:     cid,
		Timeout: 5,
		Request: &pb.ProbeRequest_Set{Set: setRequest},
	}:
	}

	select {
	case <-p.Ctx.Done():
		return fmt.Errorf("gnmi SET failed, gnmi closed")
	case <-oprTimeout.C:
		return fmt.Errorf("gnmi SET timeout on response")
	case res := <-*p.Callers[cid]:
		if res == nil {
			return fmt.Errorf("gnmi SET failed, probe stream closed")
		}
		if res.Error != "" {
			return fmt.Errorf("gnmi SET failed: %v", res.Error)
		}
		return nil
	}
}

// Sub to subscribe models streaming data specified by given path list
// run as Go routine, stream will be forwarded to caller
// caller should handle the error and terminate the routine as required
// close callerC will send Probe a duplicated sub request with the same cid
// Probe will cancel the corresponding subscription stream channel and response error message
// This Sub routine will response the error message and exit
func (p *GNMI) Sub(callerC *chan struct{}, callerD *chan *ResponseGNMI, subscriptions []*gnmipb.Subscription, timeout int64) {
	if err := p.Conn(); err != nil {
		*callerD <- &ResponseGNMI{Error: "unable to connect to Probe"}
		return
	}

	cid := p.SetCaller()
	defer func() {
		p.ClearCaller(cid)
		close(*callerD)
	}()

	encoding, _ := gnmipb.Encoding_value[ENCODING]
	subscriptionListMode := gnmipb.SubscriptionList_STREAM // pb.SubscriptionList_POLL, pb.SubscriptionList_ONCE
	subRequest := &gnmipb.SubscribeRequest{
		Request: &gnmipb.SubscribeRequest_Subscribe{
			Subscribe: &gnmipb.SubscriptionList{
				Encoding:     gnmipb.Encoding(encoding),
				Mode:         subscriptionListMode,
				Subscription: subscriptions,
				//UpdatesOnly:  true,
			},
		},
	}

	oprTimeout := time.NewTimer(time.Second * 10)
	select {
	case <-p.Ctx.Done():
		*callerD <- &ResponseGNMI{Error: "gnmi SUB request not sent, gnmi closed"}
		return
	case <-oprTimeout.C:
		*callerD <- &ResponseGNMI{Error: "gnmi SUB timeout on request"}
		return
	case <-*callerC:
		*callerD <- &ResponseGNMI{Error: "gnmi SUB request not sent, cancelled"}
		return
	case *p.ToProbe <- &pb.ProbeRequest{
		Cid:     cid,
		Timeout: timeout,
		Request: &pb.ProbeRequest_Sub{Sub: subRequest},
	}:
	}

	unsub := false
	for {
		select {
		case res := <-*p.Callers[cid]:
			if res == nil {
				*callerD <- &ResponseGNMI{Error: "probe stream closed"}
				log.Infof("subscription %v cancelled due to probe stream closed", cid)
				return
			}
			*callerD <- res
			if res.Error != "" {
				log.Infof("subscription %v cancelled due to error: %v", cid, res.Error)
				return
			}
		case <-p.Ctx.Done():
			*callerD <- &ResponseGNMI{Error: "gnmi closed"}
			log.Infof("subscription %v cancelled due to gnmi close", cid)
			return
		case <-*callerC:
			if !unsub {
				// un-subcribe
				*p.ToProbe <- &pb.ProbeRequest{Cid: cid, Request: &pb.ProbeRequest_Sub{Sub: subRequest}}
				unsub = true
			}
		}
	}
}
