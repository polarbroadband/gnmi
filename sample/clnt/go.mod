module main

go 1.14

require (
	github.com/golang/snappy v0.0.4 // indirect
	github.com/google/gnxi v0.0.0-20210716134716-cb5c55758a07
	github.com/kr/pretty v0.3.0
	github.com/kr/text v0.2.0 // indirect
	github.com/niemeyer/pretty v0.0.0-20200227124842-a10e7caefd8e // indirect
	github.com/openconfig/gnmi v0.0.0-20210707145734-c69a5df04b53
	github.com/polarbroadband/gnmi/pkg/gnmiprobe v0.0.0-00010101000000-000000000000
	github.com/polarbroadband/gnmi/pkg/probeclient v0.0.0-00010101000000-000000000000
	github.com/rogpeppe/go-internal v1.8.0 // indirect
	github.com/sirupsen/logrus v1.8.1
	github.com/stretchr/testify v1.6.1 // indirect
	golang.org/x/crypto v0.0.0-20210711020723-a769d52b0f97 // indirect
	golang.org/x/term v0.0.0-20210615171337-6886f2dfbf5b // indirect
	google.golang.org/grpc v1.39.1
	gopkg.in/check.v1 v1.0.0-20200902074654-038fdea0a05b // indirect
	gopkg.in/yaml.v3 v3.0.0-20200615113413-eeeca48fe776 // indirect
)

replace (
	github.com/polarbroadband/gnmi/pkg/gnmiprobe => ../../pkg/gnmiprobe
	github.com/polarbroadband/gnmi/pkg/probeclient => ../../pkg/probeclient
)
