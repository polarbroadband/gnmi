package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"

	pb "github.com/polarbroadband/gnmi/pkg/gnmiprobe"

	"github.com/polarbroadband/goto/util"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
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

type Client struct {
}

type WorkerNode struct {
	pb.UnimplementedProbeServer
	*util.API
	//*util.MongoOpr
	Load map[string]Client
}

func main() {
	wkr := WorkerNode{
		Load: make(map[string]Client),
		API: &util.API{
			TokenSec: TOKENSEC,
			NoAuth: []string{
				"/gnmiprobe.Probe/Healtz",
				"/gnmiprobe.Probe/ConnectProbe",
			},
			Log: log.WithField("owner", HOST),
		},
	}

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

	grpcSvr := grpc.NewServer(grpc.Creds(grpcTLS), grpc.UnaryInterceptor(wkr.AuthGrpcUnary))

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

func (wkr *WorkerNode) GetLoad() int64 {
	return int64(len(wkr.Load))
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
	s := wkr.GetLoad()
	if s >= SESSION_MAX {
		wkr.Error(w, 503, _e.String(fmt.Sprintf("%v sessions active, reach limit: %v", s, SESSION_MAX)))
	} else if err := json.NewEncoder(w).Encode(map[string]interface{}{"status": "done", "sessions": s}); err != nil {
		wkr.Error(w, 500, _e.String("erroneous api response", err))
	}
}

// Healtz response gRPC health check
func (wkr *WorkerNode) Healtz(ctx context.Context, r *pb.HealtzReq) (*pb.SvrStat, error) {
	//_e := util.NewExeErr("Healtz", HOST, "gRPC_API")
	p, _ := peer.FromContext(ctx)
	fmt.Println(p)
	fmt.Println(p.Addr.String())
	fmt.Println(p.Addr.Network())

	return &pb.SvrStat{
		Host:    HOST,
		Release: RELEASE,
		Load:    wkr.GetLoad(),
	}, nil
}
