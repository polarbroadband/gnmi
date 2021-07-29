package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	pb "github.com/polarbroadband/gnmi/pkg/gnmiprobe"

	log "github.com/sirupsen/logrus"
)

var (
	ENCODING = "JSON"
)

func init() {
	// config package level default logger
	log.SetFormatter(&log.JSONFormatter{})
	log.SetOutput(os.Stdout)
	log.SetLevel(log.TraceLevel)
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
	RLock *sync.Mutex

	Callers   map[int64]*chan *ResponseGNMI
	CallersCt int64
	CLock     *sync.Mutex

	ToProbe *chan *pb.ProbeRequest

	Config *pb.ProbeConn
}

func (p *GNMI) SetCaller() int64 {
	respCh := make(chan *ResponseGNMI)
	p.CLock.Lock()
	p.CallersCt++
	cid := p.CallersCt
	p.Callers[cid] = &respCh
	p.CLock.Unlock()
	return cid
}

func (p *GNMI) ClearCaller(cid int64) {
	p.CLock.Lock()
	delete(p.Callers, cid)
	p.CLock.Unlock()
}

func (p *GNMI) AlertCallers(err interface{}) {
	for _, c := range p.Callers {
		*c <- &ResponseGNMI{Error: fmt.Sprint(err)}
	}
}

func (p *GNMI) CloseCallers() {
	p.CLock.Lock()
	for _, c := range p.Callers {
		close(*c)
	}
	p.CLock.Unlock()
}

func (p *GNMI) Close() {
	p.RLock.Lock()
	p.Ready = false
	close(*p.ToProbe)
	p.Cancel()
	p.RLock.Unlock()
}

func (p *GNMI) Conn() error {
	p.RLock.Lock()
	defer p.RLock.Unlock()
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

	unSub := false
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
			if !unSub {
				// un-subcribe
				*p.ToProbe <- &pb.ProbeRequest{Cid: cid, Request: &pb.ProbeRequest_Sub{Sub: subRequest}}
				unSub = true
			}
		}
	}
}
