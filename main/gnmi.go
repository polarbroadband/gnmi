/*
Go 1.14 drop NPN support, use ALPN only to negotiate app layer protocol used (http/2) over TLS
To interact with SROS 7750
need to build this in Go 1.13
*/

package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/kr/pretty"
	log "github.com/sirupsen/logrus"

	"github.com/golang/protobuf/proto"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"

	"github.com/google/gnxi/utils/xpath"

	pb "github.com/openconfig/gnmi/proto/gnmi"
)

var (
	USERNAME = os.Getenv("USERNAME")
	PASSWORD = os.Getenv("PASSWORD")

	ENCODING = "JSON"

	URL_TARGET = os.Getenv("URL_TARGET")
	// CA certificate which signed the router certificate
	CERT_CA = os.Getenv("CERT_CA")

	SVR_NAME = ""

	XPATH       = os.Getenv("XPATH")
	XPATH_STATE = os.Getenv("XPATH_STATE")

	XPATH_UPDATE = os.Getenv("XPATH_UPDATE")
	UPDATE_KEY   = os.Getenv("UPDATE_KEY")
	UPDATE_VAL   = os.Getenv("UPDATE_VAL")

	/*
		// SROS only accept JSON encoding for SET
		XPATH_UPDATE = "/configure/port[port-id=1/1/c10/1]/description"
		VALUE_UPDATE = "<< EDTNABTFSE53 | 1/1/c10/1 LAG 53 >>"
	*/
)

func init() {
	// config package level default logger
	log.SetFormatter(&log.JSONFormatter{})
	log.SetOutput(os.Stdout)
	log.SetLevel(log.TraceLevel)
}

/*
use metadata.AppendToOutgoingContext to avoid RequireTransportSecurity change between no_TLS and TLS

type userCredentials struct {
	username string
	password string
}

func (a *userCredentials) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	return map[string]string{
		"username": a.username,
		"password": a.password,
	}, nil
}

func (a *userCredentials) RequireTransportSecurity() bool {
	return false
}
*/

func stream(subscribeClient pb.GNMI_SubscribeClient) error {
	for {
		if closed, err := receiveNotifications(subscribeClient); err != nil {
			return err
		} else if closed {
			return nil
		}
	}
}

func receiveNotifications(subscribeClient pb.GNMI_SubscribeClient) (bool, error) {
	for {
		res, err := subscribeClient.Recv()
		if err == io.EOF {
			return true, nil
		}
		if err != nil {
			return false, err
		}
		switch res.Response.(type) {
		case *pb.SubscribeResponse_SyncResponse:
			//log.Info("SyncResponse received")
			return false, nil
		case *pb.SubscribeResponse_Update:
			var ct interface{}
			json.Unmarshal(res.GetUpdate().GetUpdate()[0].GetVal().GetJsonVal(), &ct) // string
			fmt.Printf("%v %v\n", res.GetUpdate().GetTimestamp(), ct)
		default:
			return false, errors.New("unexpected response type")
		}
	}
}

type TargetGNMI struct {
	Url     string
	SvrName string
	Conn    *grpc.ClientConn
	CalCtx  context.Context
	CertCA  string
}

func (t *TargetGNMI) ConnNoTLS() error {
	ctx, _ := context.WithTimeout(context.Background(), time.Duration(time.Second*5))
	conn, err := grpc.DialContext(
		ctx,
		t.Url,
		// no TLS
		grpc.WithInsecure(),
		grpc.WithBlock(),
		//grpc.WithPerRPCCredentials(t.Cred),
	)
	if err != nil {
		return fmt.Errorf("fail to connect %s: %v, %v", t.Url, conn.GetState(), err)
	}
	t.Conn = conn
	return nil
}

func (t *TargetGNMI) ConnTLSTrust() error {
	ctx, _ := context.WithTimeout(context.Background(), time.Duration(time.Second*5))
	conn, err := grpc.DialContext(
		ctx,
		t.Url,
		// skip verifying target certification
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: true})),
		grpc.WithBlock(),
		grpc.WithReturnConnectionError(),
	)
	if err != nil {
		return fmt.Errorf("fail to connect %s: %v", t.Url, err)
	}
	t.Conn = conn
	return nil
}

func (t *TargetGNMI) ConnTLS() error {
	ctx, _ := context.WithTimeout(context.Background(), time.Duration(time.Second*5))
	caCert, err := credentials.NewClientTLSFromFile(t.CertCA, t.SvrName)
	if err != nil {
		return fmt.Errorf("unable to import CA certificate: %v", err)
	}
	conn, err := grpc.DialContext(
		ctx,
		t.Url,
		// use imported CA certificate
		grpc.WithTransportCredentials(caCert),
		//grpc.WithKeepaliveParams(keepalive.ClientParameters{PermitWithoutStream: true}),
		/*grpc.WithConnectParams(grpc.ConnectParams{
			Backoff: backoff.Config{
				BaseDelay:  time.Second,
				Multiplier: 1.6,
				Jitter:     0.2,
				MaxDelay:   10,
			},
			MinConnectTimeout: time.Second * 20,
		}),*/
		grpc.WithBlock(),
		grpc.WithReturnConnectionError(),
	)
	if err != nil {
		return fmt.Errorf("fail to connect %s: %v", t.Url, err)
	}
	t.Conn = conn
	return nil
}

func main() {
	fmt.Printf("\n\nHello gNMI\n\n")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	target := TargetGNMI{
		Url:     URL_TARGET,
		SvrName: SVR_NAME,
		CertCA:  CERT_CA,
		CalCtx:  metadata.AppendToOutgoingContext(ctx, "username", USERNAME, "password", PASSWORD),
	}
	var err error
	switch target.CertCA {
	case "_NO_TLS_":
		err = target.ConnNoTLS()
	case "":
		err = target.ConnTLSTrust()
	default:
		err = target.ConnTLS()
	}
	if err != nil {
		log.Fatal(err)
	}
	defer target.Conn.Close()
	log.Infof("Connecting %s, transport state: %v", target.Url, target.Conn.GetState())

	client := pb.NewGNMIClient(target.Conn)

	// Capabilities
	capResponse, err := client.Capabilities(target.CalCtx, &pb.CapabilityRequest{})
	if err != nil {
		log.Fatalf("error in getting capabilities: %v", err)
	}

	fmt.Println("== CapabilitiesResponse:\n", proto.MarshalTextString(capResponse))

	encoding, _ := pb.Encoding_value[ENCODING]

	// SET
	if XPATH_UPDATE != "" && UPDATE_KEY != "" && UPDATE_VAL != "" {
		pbPath, err := xpath.ToGNMIPath(XPATH_UPDATE)
		if err != nil {
			log.Fatalf("error in parsing xpath %q to gnmi path: %v", XPATH_UPDATE, err)
		}
		toUpdate, err := json.Marshal(map[string]interface{}{UPDATE_KEY: UPDATE_VAL})
		if err != nil {
			log.Fatalf("unable to assembly update item: %v", err)
		}
		setRequest := &pb.SetRequest{
			Delete:  nil,
			Replace: nil,
			Update: []*pb.Update{{
				Path: pbPath,
				Val: &pb.TypedValue{
					//Value: &pb.TypedValue_StringVal{StringVal: VALUE_UPDATE},

					// SROS only accept JSON encoding for SET
					Value: &pb.TypedValue_JsonVal{JsonVal: toUpdate},
				},
			}},
		}
		setResponse, err := client.Set(target.CalCtx, setRequest)
		if err != nil {
			log.Fatalf("Set failed: %v", err)
		}
		fmt.Println("== SetResponse:\n", proto.MarshalTextString(setResponse))
	}

	// GET
	if XPATH != "" {
		pbPath, err := xpath.ToGNMIPath(XPATH)
		if err != nil {
			log.Fatalf("error in parsing xpath %q to gnmi path", XPATH)
		}
		pbPathList := []*pb.Path{pbPath}
		pbModelDataList := []*pb.ModelData{}

		getRequest := &pb.GetRequest{
			Encoding:  pb.Encoding(encoding),
			Path:      pbPathList,
			UseModels: pbModelDataList,
		}
		fmt.Println("== GetRequest:\n", proto.MarshalTextString(getRequest))

		getResponse, err := client.Get(target.CalCtx, getRequest)
		if err != nil {
			log.Fatalf("Get failed: %v", err)
		}

		for _, notification := range getResponse.GetNotification() {
			for _, update := range notification.GetUpdate() {
				var res map[string]interface{}
				json.Unmarshal(update.GetVal().GetJsonVal(), &res)
				pretty.Printf("\nGetResponse *****************\n%# v\n", res)
				fmt.Printf("\n\nport %s %s\n\n", res["port-id"], res["description"])
			}
		}
	}

	// Subscribe
	if XPATH_STATE != "" {
		subscribeClient, err := client.Subscribe(target.CalCtx)
		if err != nil {
			log.Fatalf("Error creating GNMI_SubscribeClient: %v", err)
		}
		pbPath, err := xpath.ToGNMIPath(XPATH_STATE)
		if err != nil {
			log.Fatalf("error in parsing xpath %q to gnmi path", XPATH_STATE)
		}
		subscriptionListMode := pb.SubscriptionList_STREAM // pb.SubscriptionList_POLL, pb.SubscriptionList_ONCE
		subscriptions := []*pb.Subscription{{
			Path:           pbPath,
			Mode:           pb.SubscriptionMode_SAMPLE, // pb.SubscriptionMode_ON_CHANGE, pb.SubscriptionMode_TARGET_DEFINED
			SampleInterval: 5000000000,                 // ns, unit64
			//SuppressRedundant: true,
			//HeartbeatInterval: 30000000000, // ns, unit64
		}}

		request := &pb.SubscribeRequest{
			Request: &pb.SubscribeRequest_Subscribe{
				Subscribe: &pb.SubscriptionList{
					Encoding:     pb.Encoding(encoding),
					Mode:         subscriptionListMode,
					Subscription: subscriptions,
					//UpdatesOnly:  true,
				},
			},
		}
		fmt.Println("== SubscribeRequest:\n", proto.MarshalTextString(request))

		if err := subscribeClient.Send(request); err != nil {
			log.Fatalf("Failed to send request: %v", err)
		}
		if err := stream(subscribeClient); err != nil {
			log.Fatalf("Error using STREAM mode: %v", err)
		}
	}
}
