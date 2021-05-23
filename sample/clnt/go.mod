module main

go 1.14

require (
	github.com/google/gnxi v0.0.0-20210423111716-4b504ef806a7
	github.com/kr/pretty v0.2.1
	github.com/kr/text v0.2.0 // indirect
	github.com/openconfig/gnmi v0.0.0-20210430192044-ab96b57c5113
	github.com/polarbroadband/gnmi/pkg/client v0.0.0-00010101000000-000000000000
	github.com/polarbroadband/gnmi/pkg/gnmiprobe v0.0.0-00010101000000-000000000000
	github.com/sirupsen/logrus v1.8.1
	golang.org/x/sys v0.0.0-20210521203332-0cec03c779c1 // indirect
	google.golang.org/genproto v0.0.0-20210521181308-5ccab8a35a9a // indirect
	google.golang.org/grpc v1.38.0
)

replace (
	github.com/polarbroadband/gnmi/pkg/client => ../../pkg/client
	github.com/polarbroadband/gnmi/pkg/gnmiprobe => ../../pkg/gnmiprobe
)
