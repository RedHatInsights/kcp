package authorization

import (
	"context"

	"github.com/kcp-dev/kcp/pkg/client/informers/externalversions"
	"github.com/kcp-dev/logicalcluster/v2"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/client-go/tools/cache"
)

func NewEntitlementAuthorizer(informers externalversions.SharedInformerFactory) authorizer.Authorizer {
	return &EntitlementAuthorizer{entitlementIndexer: informers.Apis().V1alpha1().Entitlements().Informer().GetIndexer()}
}

type EntitlementAuthorizer struct {
	entitlementIndexer cache.Indexer
}

func (a *EntitlementAuthorizer) Authorize(ctx context.Context, attr authorizer.Attributes) (authorized authorizer.Decision, reason string, err error) {
	lcluster, err := genericapirequest.ClusterNameFrom(ctx)
	if err != nil {
		return authorizer.DecisionNoOpinion, "internal error", err
	}

	switch attr.GetResource() {
	case "apiexports":
		if attr.GetVerb() != "bind" {
			return notApplicable()
		}
		return a.authorizeExportBind(lcluster, attr)
	case "apibindings":
		return a.authorizeBindingOperation(lcluster, attr)
	case "entitlements":
		return a.authorizeEntitlementOperation(attr)
	default:
		return notApplicable()
	}
}

func (a *EntitlementAuthorizer) authorizeExportBind(clusterName logicalcluster.Name, attr authorizer.Attributes) (authorized authorizer.Decision, reason string, err error) {
	//clusterName is service provider workspace
	return notApplicable()
}

func (a *EntitlementAuthorizer) authorizeBindingOperation(clusterName logicalcluster.Name, attr authorizer.Attributes) (authorized authorizer.Decision, reason string, err error) {
	//clusterName is consumer workspace
	return notApplicable()
}

func (a *EntitlementAuthorizer) authorizeEntitlementOperation(attr authorizer.Attributes) (authorized authorizer.Decision, reason string, err error) {
	if attr.GetVerb() == "get" || attr.GetVerb() == "list" {
		return notApplicable()
	}

	if attr.GetUser().GetName() == "kcp-admin" { //Hack to allow the kube admin to create entitlements. This should actually apply to whatever privileged controller/user would normally do this.
		return notApplicable()
	}

	return authorizer.DecisionDeny, "Users cannot modify entitlements", nil
}

func notApplicable() (authorized authorizer.Decision, reason string, err error) {
	return authorizer.DecisionNoOpinion, "Not applicable", nil
}
