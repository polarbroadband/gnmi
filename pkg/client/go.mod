module github.com/polarbroadband/gnmi/pkg/client

go 1.16

replace github.com/polarbroadband/gnmi/pkg/gnmiprobe => ../gnmiprobe

require (
	github.com/openconfig/gnmi v0.0.0-20210430192044-ab96b57c5113
	github.com/polarbroadband/gnmi/pkg/gnmiprobe v0.0.0-00010101000000-000000000000
	github.com/sirupsen/logrus v1.8.1
	github.com/stretchr/testify v1.7.0 // indirect
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b // indirect
)
