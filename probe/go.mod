module main

go 1.16

require (
	github.com/aws/aws-sdk-go v1.38.45 // indirect
	github.com/felixge/httpsnoop v1.0.2 // indirect
	github.com/gorilla/handlers v1.5.1
	github.com/gorilla/mux v1.8.0
	github.com/klauspost/compress v1.12.2 // indirect
	github.com/openconfig/gnmi v0.0.0-20210430192044-ab96b57c5113
	github.com/polarbroadband/gnmi/pkg/gnmiprobe v0.0.0-00010101000000-000000000000
	github.com/polarbroadband/goto v0.2.35
	github.com/sirupsen/logrus v1.8.1
	go.mongodb.org/mongo-driver v1.5.2 // indirect
	golang.org/x/crypto v0.0.0-20210513164829-c07d793c2f9a // indirect
	golang.org/x/term v0.0.0-20210503060354-a79de5458b56 // indirect
	google.golang.org/grpc v1.38.0
)

replace github.com/polarbroadband/gnmi/pkg/gnmiprobe => ../pkg/gnmiprobe
