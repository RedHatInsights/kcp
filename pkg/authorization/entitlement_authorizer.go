package authorization

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/kcp-dev/kcp/pkg/apis/apis/v1alpha1"
	"github.com/kcp-dev/kcp/pkg/client/informers/externalversions"
	"github.com/kcp-dev/kcp/pkg/indexers"
	"github.com/kcp-dev/logicalcluster/v2"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/client-go/tools/cache"
)

func NewEntitlementAuthorizer(informers externalversions.SharedInformerFactory) authorizer.Authorizer {
	return &EntitlementAuthorizer{
		entitlementIndexer: informers.Apis().V1alpha1().Entitlements().Informer().GetIndexer(),
		apiExportIndexer:   informers.Apis().V1alpha1().APIExports().Informer().GetIndexer(),
	}
}

type EntitlementAuthorizer struct {
	entitlementIndexer cache.Indexer
	apiExportIndexer   cache.Indexer
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
	//If we presume the org group name is the same as the org workspace name, it's possible to find the org workspace and retrieve entitlements
	//We get get the export being bound from the current workspace, and get the service name from it
	//If no entitlement exists for the export, prevent the bind. Otherwise, delegate.
	user := attr.GetUser()
	org, err := getTenantId(user)
	if err != nil {
		return authorizer.DecisionNoOpinion, "internal error", err
	}

	consumerCluster := "root:" + org //Hack to find the consumer cluster. Assumes org cluster has the same name as the value in the org group.
	entitlements, err := a.entitlementIndexer.ByIndex(indexers.ByLogicalCluster, consumerCluster)
	if err != nil {
		return authorizer.DecisionNoOpinion, "internal error", err
	}

	for _, obj := range entitlements {
		entitlement := obj.(*v1alpha1.Entitlement)

		if entitlement.Spec.Service == attr.GetName() {
			return authorizer.DecisionAllow, "Entitlements are satisfied.", nil //Permission to create the binding in the consumer workspace is handled separately
		}
	}

	return authorizer.DecisionDeny, fmt.Sprintf("Required entitlement not found in workspace %q for service %q", consumerCluster, attr.GetResource()), nil
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

func getTenantId(usr user.Info) (string, error) {
	for _, group := range usr.GetGroups() {
		if strings.HasPrefix(group, "org/") {
			return group[4:], nil
		}
	}
	return "", errors.New("organization group not found")
}

func notApplicable() (authorized authorizer.Decision, reason string, err error) {
	return authorizer.DecisionNoOpinion, "Not applicable", nil
}
