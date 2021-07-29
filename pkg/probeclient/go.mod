module github.com/polarbroadband/gnmi/pkg/probeclient

go 1.16

replace github.com/polarbroadband/gnmi/pkg/gnmiprobe => ../gnmiprobe

require (
	github.com/aws/aws-sdk-go v1.38.50 // indirect
	github.com/klauspost/compress v1.12.3 // indirect
	github.com/openconfig/gnmi v0.0.0-20210527163611-d3a3e30199da
	github.com/polarbroadband/gnmi/pkg/gnmiprobe v0.0.0-00010101000000-000000000000
	github.com/polarbroadband/goto v0.2.36
	github.com/sirupsen/logrus v1.8.1
	go.mongodb.org/mongo-driver v1.5.2 // indirect
	golang.org/x/crypto v0.0.0-20210513164829-c07d793c2f9a // indirect
	golang.org/x/net v0.0.0-20210525063256-abc453219eb5 // indirect
	golang.org/x/sys v0.0.0-20210525143221-35b2ab0089ea // indirect
	golang.org/x/term v0.0.0-20210503060354-a79de5458b56 // indirect
	google.golang.org/grpc v1.38.0
	google.golang.org/protobuf v1.26.0
)
