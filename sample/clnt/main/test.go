package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	pb "github.com/polarbroadband/gnmi/pkg/gnmiprobe"

	"github.com/polarbroadband/gnmi/pkg/client"

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
	if res, err := probe.Healtz(gCtx, &pb.HealtzReq{}); err != nil {
		log.Fatalf("%s gRPC healtz check fail: %v", PROBE, err)
	} else {
		fmt.Printf("\n*** probe gRPC healtz check ***\nHost: %s\nRel: %s\nLoad: %v\n", res.GetHost(), res.GetRelease(), res.GetLoad())
	}

	psm := client.GNMI{
		Ctx:         gCtx,
		Cancel:      gCancel,
		ProbeClient: probe,
		Ready:       false,
		RLock:       &sync.Mutex{},
		Callers:     make(map[int64]*chan *client.ResponseGNMI),
		CallersCt:   0,
		CLock:       &sync.Mutex{},

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

	psm1 := client.GNMI{
		Ctx:         gCtx,
		Cancel:      gCancel,
		ProbeClient: probe,
		Ready:       false,
		RLock:       &sync.Mutex{},
		Callers:     make(map[int64]*chan *client.ResponseGNMI),
		CallersCt:   0,
		CLock:       &sync.Mutex{},

		Config: &pb.ProbeConn{
			TLS:  true,
			Cer:  "",
			Host: "172.25.130.74",
			Port: "57400",
			Usr:  "gnmi",
			Pwd:  "telus123",
		},
	}
	defer psm1.Close()

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
		cd := make(chan *client.ResponseGNMI)
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
					fmt.Printf("-- 1 -- %v %v %v\n", notification.GetPrefix(), notification.GetTimestamp(), ct)
				}

			}
		}
	}()

	cc1 := make(chan struct{})
	go func() {
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
		cd := make(chan *client.ResponseGNMI)
		go psm1.Sub(&cc1, &cd, subscriptions, 20)

		for res := range cd {
			if res.Error != "" {
				log.Info(res.Error)
				return
			}

			for _, notification := range res.Resp {
				for _, update := range notification.GetUpdate() {
					var ct interface{}
					json.Unmarshal(update.GetVal().GetJsonVal(), &ct) // string
					fmt.Printf("-- 2 -- %v %v %v\n", notification.GetPrefix(), notification.GetTimestamp(), ct)
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
		cd := make(chan *client.ResponseGNMI)
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
