package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	pb "github.com/polarbroadband/gnmi/pkg/gnmiprobe"

	client "github.com/polarbroadband/gnmi/pkg/probeclient"

	"github.com/google/gnxi/utils/xpath"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/kr/pretty"
	log "github.com/sirupsen/logrus"
)

var (
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

	hold := make(chan struct{})

	if res, err := http.Get("http://" + PROBE + ":8060/healtz"); err != nil {
		log.Panicf("%s healtz check fail: %v", PROBE, err)
	} else {
		var rb map[string]interface{}
		json.NewDecoder(res.Body).Decode(&rb)
		res.Body.Close()
		pretty.Printf("\n*** probe healtz check ***\n%# v\n", rb)
	}

	if res, err := http.Get("http://" + PROBE + ":8060/ready"); err != nil {
		log.Panicf("%s load check fail: %v", PROBE, err)
	} else {
		var rb map[string]interface{}
		json.NewDecoder(res.Body).Decode(&rb)
		res.Body.Close()
		pretty.Printf("\n*** probe load check ***\n%# v\n", rb)
	}

	caCer, err := credentials.NewClientTLSFromFile("/appsrc/cert/ca.cert", "")
	if err != nil {
		log.Panicf("unable to import ca certificate: %v", err)
	}
	// Set up TLS connection to the server
	probeConn, err := grpc.Dial(PROBE+":50051", grpc.WithTransportCredentials(caCer))
	if err != nil {
		log.Panic("unable to connect %s: %v", PROBE, err)
	}
	defer probeConn.Close()
	probe := pb.NewProbeClient(probeConn)
	gCtx, gCancel := context.WithCancel(context.Background())
	defer gCancel()
	if res, err := probe.Healtz(gCtx, &pb.HealtzReq{}); err != nil {
		log.Panicf("%s gRPC healtz check fail: %v", PROBE, err)
	} else {
		fmt.Printf("\n*** probe gRPC healtz check ***\nHost: %s\nRel: %s\nLoad: %v\n", res.GetHost(), res.GetRelease(), res.GetLoad())
	}

	psm1 := client.GNMI{
		Probe: probe,
		Param: &pb.ProbeConn{
			TLS:  false,
			Cer:  "",
			Host: "172.25.208.194",
			Port: "57400",
			Usr:  "gnmi",
			Pwd:  "telus123",
		},
	}
	if err := psm1.GnInit(); err != nil {
		log.Panicf("fail to init: %v", err)
	}
	defer psm1.GnClose()

	psm2 := client.GNMI{
		Probe: probe,
		Param: &pb.ProbeConn{
			TLS:  true,
			Cer:  "",
			Host: "172.25.130.74",
			Port: "57400",
			Usr:  "gnmi",
			Pwd:  "telus123",
		},
	}
	defer psm2.GnClose()

	secP, _ := xpath.ToGNMIPath("/configure/port[port-id=1/1/c10/1]")
	resp, err := psm1.GnGet([]*gnmipb.Path{secP})
	if err != nil {
		log.Panic(err)
	}
	for _, notification := range resp {
		for _, update := range notification.GetUpdate() {
			var res map[string]interface{}
			json.Unmarshal(update.GetVal().GetJsonVal(), &res)
			//pretty.Printf("\nGetResponse *****************%v\n%# v\n", notification.GetPrefix(), res)
			fmt.Printf("\n++ 1 ++\nport %s %s\n\n", res["port-id"], res["description"])
		}
	}

	ctx1, cancel1 := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel1()
	go func() {
		defer fmt.Println("++++++++++ stream1 closed")
		secP, _ := xpath.ToGNMIPath("/state/port[port-id=1/1/c1/1]/statistics/in-packets")
		subscriptions := []*gnmipb.Subscription{
			{
				Path:           secP,
				Mode:           gnmipb.SubscriptionMode_SAMPLE, // pb.SubscriptionMode_ON_CHANGE, pb.SubscriptionMode_TARGET_DEFINED
				SampleInterval: 1000000000,                     // ns, unit64
				//SuppressRedundant: true,
				//HeartbeatInterval: 30000000000, // ns, unit64
			},
		}
		stream, err := psm1.GnSubscribe(ctx1, subscriptions)
		if err != nil {
			log.Panic(err)
		}
		for {
			select {
			case <-ctx1.Done():
				return
			default:
				data, err := stream.Recv()
				if err == io.EOF {
					return
				}
				if err != nil {
					log.Info(err)
					return
				}
				if res, ok := data.Response.(*gnmipb.SubscribeResponse_Update); ok {
					resm := map[string]interface{}{}
					for _, update := range res.Update.GetUpdate() {
						keyChain := []string{}
						for _, k := range update.Path.GetElem() {
							keyChain = append(keyChain, k.GetName())
						}
						var ct interface{}
						json.Unmarshal(update.GetVal().GetJsonVal(), &ct) // string
						resm[strings.Join(keyChain, "/")] = ct
					}
					fmt.Printf("--1---- %v %v %v\n", res.Update.GetPrefix(), res.Update.GetTimestamp(), resm)
				}
			}
		}
	}()

	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second*15)
	defer cancel2()
	go func() {
		defer fmt.Println("++++++++++ stream2 closed")
		secP, _ := xpath.ToGNMIPath("/state/port[port-id=1/1/c1/1]/statistics/in-packets")
		subscriptions := []*gnmipb.Subscription{
			{
				Path:           secP,
				Mode:           gnmipb.SubscriptionMode_SAMPLE, // pb.SubscriptionMode_ON_CHANGE, pb.SubscriptionMode_TARGET_DEFINED
				SampleInterval: 2000000000,                     // ns, unit64
				//SuppressRedundant: true,
				//HeartbeatInterval: 30000000000, // ns, unit64
			},
		}
		stream, err := psm2.GnSubscribe(ctx2, subscriptions)
		if err != nil {
			log.Panic(err)
		}
		for {
			select {
			case <-ctx2.Done():
				return
			default:
				data, err := stream.Recv()
				if err == io.EOF {
					return
				}
				if err != nil {
					log.Info(err)
					return
				}
				if res, ok := data.Response.(*gnmipb.SubscribeResponse_Update); ok {
					for uf, update := range res.Update.GetUpdate() {
						var ct interface{}
						json.Unmarshal(update.GetVal().GetJsonVal(), &ct) // string
						fmt.Printf("--2--%v-- %v %v %v\n", uf, res.Update.GetPrefix(), res.Update.GetTimestamp(), ct)

					}
				}
			}
		}
	}()

	time.Sleep(time.Second * 5)
	cancel1()

	time.Sleep(time.Second * 1)
	secP, _ = xpath.ToGNMIPath("/configure/port[port-id=1/1/c11/1]")
	resp, err = psm1.GnGet([]*gnmipb.Path{secP})
	if err != nil {
		log.Panic(err)
	}
	for _, notification := range resp {
		for _, update := range notification.GetUpdate() {
			var res map[string]interface{}
			json.Unmarshal(update.GetVal().GetJsonVal(), &res)
			fmt.Printf("\n++ 2 ++\nport %s %s\n\n", res["port-id"], res["description"])
		}
	}

	time.Sleep(time.Second * 5)
	secP, _ = xpath.ToGNMIPath("/configure/port[port-id=1/1/c1/1]")
	resp, err = psm1.GnGet([]*gnmipb.Path{secP})
	if err != nil {
		log.Panic(err)
	}
	for _, notification := range resp {
		for _, update := range notification.GetUpdate() {
			var res map[string]interface{}
			json.Unmarshal(update.GetVal().GetJsonVal(), &res)
			fmt.Printf("\n++ 3 ++\nport %s %s\n\n", res["port-id"], res["description"])
		}
	}

	time.Sleep(time.Second * 5)
	close(hold)

	<-hold
}
