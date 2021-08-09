module main

go 1.16

require (
	github.com/aws/aws-sdk-go v1.40.10 // indirect
	github.com/felixge/httpsnoop v1.0.2 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/gorilla/handlers v1.5.1
	github.com/gorilla/mux v1.8.0
	github.com/klauspost/compress v1.13.3 // indirect
	github.com/openconfig/gnmi v0.0.0-20210707145734-c69a5df04b53
	github.com/polarbroadband/gnmi/pkg/gnmiprobe v0.0.0-20210809202233-c4828663be8a
	github.com/polarbroadband/goto v0.2.36
	github.com/sirupsen/logrus v1.8.1
	go.mongodb.org/mongo-driver v1.7.1 // indirect
	golang.org/x/crypto v0.0.0-20210711020723-a769d52b0f97 // indirect
	golang.org/x/net v0.0.0-20210805182204-aaa1db679c0d // indirect
	golang.org/x/sys v0.0.0-20210806184541-e5e7981a1069 // indirect
	golang.org/x/term v0.0.0-20210615171337-6886f2dfbf5b // indirect
	google.golang.org/genproto v0.0.0-20210809142519-0135a39c2737 // indirect
	google.golang.org/grpc v1.39.1
)

//replace github.com/polarbroadband/gnmi/pkg/gnmiprobe => ../pkg/gnmiprobe
