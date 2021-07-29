module main

go 1.16

replace github.com/polarbroadband/gnmi/pkg/gnmiprobe => ../../pkg/gnmiprobe

require (
	github.com/kr/pretty v0.2.1
	github.com/kr/text v0.2.0 // indirect
	github.com/polarbroadband/gnmi/pkg/gnmiprobe v0.0.0-00010101000000-000000000000
	github.com/sirupsen/logrus v1.8.1
	google.golang.org/grpc v1.38.0
)
