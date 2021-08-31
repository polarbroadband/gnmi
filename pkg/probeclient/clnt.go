package probeclient

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/polarbroadband/gnmi/pkg/gnmiprobe"
	"github.com/polarbroadband/goto/util"

	log "github.com/sirupsen/logrus"
)

func init() {
	// config package level default logger
	log.SetFormatter(&log.JSONFormatter{})
	log.SetOutput(os.Stdout)
	log.SetLevel(log.TraceLevel)
}

var (
	ENCODING        = "JSON"
	ProtojsonOption = protojson.MarshalOptions{
		Multiline:     true,
		AllowPartial:  true,
		UseProtoNames: true,
	}
)

// GnmiPathToXPath convert Path elements to xpath string, no leading "/"
func GnmiPathToXPath(p *gnmipb.Path) string {
	if p == nil {
		return ""
	}
	sb := strings.Builder{}
	if p.Origin != "" {
		sb.WriteString(p.Origin)
		sb.WriteString(":")
	}
	elems := p.GetElem()
	numElems := len(elems)
	for i, pe := range elems {
		sb.WriteString(pe.GetName())
		for k, v := range pe.GetKey() {
			sb.WriteString("[")
			sb.WriteString(k)
			sb.WriteString("=")
			sb.WriteString(v)
			sb.WriteString("]")
		}
		if i+1 != numElems {
			sb.WriteString("/")
		}
	}
	return sb.String()
}

type GNMI struct {
	ProbeID      string
	Param        *pb.ProbeConn `json:"gnmi_param"`
	Probe        pb.ProbeClient
	Token        util.AuthToken
	Capabilities *gnmipb.CapabilityResponse
}

func (g *GNMI) GnClose() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	g.Probe.Disconnect(ctx, &pb.ProbeBase{ID: g.ProbeID}, grpc.PerRPCCredentials(g.Token))
	log.Infof("probe %s closed, target %s:%s disconnected", g.ProbeID, g.Param.GetHost(), g.Param.GetPort())
}

func (g *GNMI) GnInit() error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	p, err := g.Probe.Connect(ctx, g.Param, grpc.PerRPCCredentials(g.Token))
	if err != nil {
		return fmt.Errorf("unable to connect target %s:%s, %v", g.Param.GetHost(), g.Param.GetPort(), err)
	}
	g.ProbeID = p.GetID()
	log.Infof("probe %s initialized, target %s:%s connected", g.ProbeID, g.Param.GetHost(), g.Param.GetPort())

	c, err := g.Probe.Capability(ctx, &pb.ProbeBase{ID: g.ProbeID}, grpc.PerRPCCredentials(g.Token))
	if err != nil {
		return fmt.Errorf("unable to get target %s:%s capability: %v", g.Param.GetHost(), g.Param.GetPort(), err)
	}
	g.Capabilities = c

	//fmt.Printf("\n++++++ %s:%s Capabilities ++++++\n%s\n", g.Param.GetHost(), g.Param.GetPort(), ProtojsonOption.Format(g.Capabilities))
	return nil

}

func (g *GNMI) GnCapability() error {
	if g.ProbeID == "" {
		return g.GnInit()
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	p, err := g.Probe.Capability(ctx, &pb.ProbeBase{ID: g.ProbeID}, grpc.PerRPCCredentials(g.Token))
	if err != nil {
		return err
	}
	g.Capabilities = p
	return nil
}

func (g *GNMI) GnGet(pathList []*gnmipb.Path) ([]*gnmipb.Notification, error) {
	if g.ProbeID == "" {
		if err := g.GnInit(); err != nil {
			return nil, err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	encoding, _ := gnmipb.Encoding_value[ENCODING]
	pbModelDataList := []*gnmipb.ModelData{}
	getRequest := &gnmipb.GetRequest{
		Encoding:  gnmipb.Encoding(encoding),
		Path:      pathList,
		UseModels: pbModelDataList,
	}
	resp, err := g.Probe.Get(ctx, &pb.GetRequest{
		ID:      g.ProbeID,
		Request: getRequest,
	}, grpc.PerRPCCredentials(g.Token))
	if err != nil {
		return nil, err
	}
	return resp.GetNotification(), nil
}

// Update to update the target model fields by gNMI SET
// only accept key/value pairs
func (g *GNMI) GnUpdate(path *gnmipb.Path, val map[string]interface{}) error {
	if g.ProbeID == "" {
		if err := g.GnInit(); err != nil {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

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
	_, err = g.Probe.Set(ctx, &pb.SetRequest{
		ID:      g.ProbeID,
		Request: setRequest,
	}, grpc.PerRPCCredentials(g.Token))
	if err != nil {
		return err
	}
	return nil
}

// Replace to replace the target model fields by gNMI SET
// only accept key/value pairs
func (g *GNMI) GnReplace(path *gnmipb.Path, val map[string]interface{}) error {
	if g.ProbeID == "" {
		if err := g.GnInit(); err != nil {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

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
	_, err = g.Probe.Set(ctx, &pb.SetRequest{
		ID:      g.ProbeID,
		Request: setRequest,
	}, grpc.PerRPCCredentials(g.Token))
	if err != nil {
		return err
	}
	return nil
}

// Delete to delete the target model fields by gNMI SET
func (g *GNMI) GnDelete(pathList []*gnmipb.Path) error {
	if g.ProbeID == "" {
		if err := g.GnInit(); err != nil {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	setRequest := &gnmipb.SetRequest{
		Delete: pathList,
	}
	_, err := g.Probe.Set(ctx, &pb.SetRequest{
		ID:      g.ProbeID,
		Request: setRequest,
	}, grpc.PerRPCCredentials(g.Token))
	if err != nil {
		return err
	}
	return nil
}

// Subscribe return Probe stream handle, which emits data and error
// caller terminate the stream by cancel the ctx
// caller should handle the error
func (g *GNMI) GnSubscribe(ctx context.Context, subscriptions []*gnmipb.Subscription) (pb.Probe_SubscribeClient, error) {
	if g.ProbeID == "" {
		if err := g.GnInit(); err != nil {
			return nil, err
		}
	}
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
	return g.Probe.Subscribe(ctx, &pb.SubscribeRequest{
		ID:      g.ProbeID,
		Request: subRequest,
	}, grpc.PerRPCCredentials(g.Token))
}
