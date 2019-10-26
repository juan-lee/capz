module github.com/juan-lee/capz

go 1.12

require (
	github.com/Azure/azure-sdk-for-go v34.4.0+incompatible
	github.com/Azure/go-autorest v13.0.2+incompatible // indirect
	github.com/Azure/go-autorest/autorest v0.9.1
	github.com/Azure/go-autorest/autorest/azure/auth v0.3.0
	github.com/Azure/go-autorest/autorest/to v0.3.0
	github.com/Azure/go-autorest/autorest/validation v0.2.0 // indirect
	github.com/apex/log v1.1.1
	github.com/go-logr/logr v0.1.0
	github.com/onsi/ginkgo v1.10.1
	github.com/onsi/gomega v1.7.0
	github.com/pkg/errors v0.8.1
	github.com/satori/go.uuid v1.2.0 // indirect
	k8s.io/apimachinery v0.0.0-20190817020851-f2f3a405f61d
	k8s.io/client-go v0.0.0-20190918200256-06eb1244587a
	sigs.k8s.io/cluster-api v0.2.6
	sigs.k8s.io/controller-runtime v0.3.0
	sigs.k8s.io/controller-tools v0.2.1 // indirect
)

replace sigs.k8s.io/cluster-api => github.com/juan-lee/cluster-api v0.2.2-0.20191026135150-3538648627d5
