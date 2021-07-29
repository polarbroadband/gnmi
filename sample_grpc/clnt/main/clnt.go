package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	pb "github.com/polarbroadband/gnmi/pkg/gnmiprobe"

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
	if res, err := probe.Healtz(gCtx, &pb.HealtzReq{}); err != nil {
		log.Fatalf("%s gRPC healtz check fail: %v", PROBE, err)
	} else {
		fmt.Printf("\n*** probe gRPC healtz check ***\nHost: %s\nRel: %s\nLoad: %v\n", res.GetHost(), res.GetRelease(), res.GetLoad())
	}

	hold := make(chan struct{})
	<-hold
}
