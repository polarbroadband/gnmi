module main

go 1.16

require (
	github.com/aws/aws-sdk-go v1.40.10 // indirect
	github.com/felixge/httpsnoop v1.0.2 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/gorilla/handlers v1.5.1
	github.com/gorilla/mux v1.8.0
	github.com/klauspost/compress v1.13.1 // indirect
	github.com/openconfig/gnmi v0.0.0-20210707145734-c69a5df04b53
	github.com/polarbroadband/gnmi/pkg/gnmiprobe v0.0.0-00010101000000-000000000000
	github.com/polarbroadband/goto v0.2.36
	github.com/sirupsen/logrus v1.8.1
	go.mongodb.org/mongo-driver v1.7.0 // indirect
	golang.org/x/crypto v0.0.0-20210711020723-a769d52b0f97 // indirect
	golang.org/x/net v0.0.0-20210726213435-c6fcb2dbf985 // indirect
	golang.org/x/sys v0.0.0-20210630005230-0f9fa26af87c // indirect
	golang.org/x/term v0.0.0-20210615171337-6886f2dfbf5b // indirect
	google.golang.org/genproto v0.0.0-20210729151513-df9385d47c1b // indirect
	google.golang.org/grpc v1.39.0
)

replace github.com/polarbroadband/gnmi/pkg/gnmiprobe => ../pkg/gnmiprobe
