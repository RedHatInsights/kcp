package customadmission

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"k8s.io/apiserver/pkg/authentication/user"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/tools/cache"

	"github.com/kcp-dev/kcp/pkg/apis/apis/v1alpha1"
	apisv1alpha1 "github.com/kcp-dev/kcp/pkg/apis/apis/v1alpha1"
	kcpinformers "github.com/kcp-dev/kcp/pkg/client/informers/externalversions"
	"github.com/kcp-dev/kcp/pkg/indexers"
)

const (
	PluginName = "apis.kcp.dev/CustomAdmission"
)

var aspianHACBSUsedQuota = 0
var bspianAppStudioUsedQuota = 0

// Register registers the reserved metadata plugin for creation and updates.
// Deletion and connect operations are not relevant as not object changes are expected here.
func Register(plugins *admission.Plugins) {
	plugins.Register(PluginName,
		func(config io.Reader) (admission.Interface, error) {
			return NewMutatingPCustomAdmission(), nil
		})
}

// Test
var _ admission.MutationInterface = &CustomAdmission{}
var _ admission.ValidationInterface = &CustomAdmission{}
var _ admission.InitializationValidator = &CustomAdmission{}

type CustomAdmission struct {
	*admission.Handler
	entitlementIndexer      cache.Indexer
	metadataClient          metadata.Interface
	apiBindingsHasSynced    cache.InformerSynced
	apiEntitlementHasSynced cache.InformerSynced
}

func (m *CustomAdmission) Admit(ctx context.Context, a admission.Attributes, o admission.ObjectInterfaces) (err error) {
	if a.GetSubresource() != "" {
		return nil
	}

	_, ok := a.GetObject().(metav1.Object)
	if !ok {
		return fmt.Errorf("got type %T, expected metav1.Object", a.GetObject())
	}

	user := a.GetUserInfo()
	org := getTenantId(user)
	if err != nil {
		fmt.Println(err)
		return err
	}
	if org != "" {
		consumerCluster := "root:" + org
		entitlements, err := m.entitlementIndexer.ByIndex(indexers.ByLogicalCluster, consumerCluster)
		if err != nil {
			return err
		}
		for _, obj := range entitlements {
			entitlement := obj.(*v1alpha1.Entitlement)

			// TODO - the way we have defined our API resource schema - makes it difficult to tie the
			// request back to a field in the entitlement. Ideally: a service porovider, service link back to the
			// entitlement would make the below checks for orgs and kind vanish and we can use the link, to iterate over the
			// entitlement and tie it back to the request.
			if isPresentInArray("org/aspian", user.GetGroups()) {
				if a.GetKind().Kind == "Pipeline" {
					configuredLimit, _ := strconv.Atoi(entitlement.Spec.QuotaItems[0].Limits)
					if aspianHACBSUsedQuota < configuredLimit {
						aspianHACBSUsedQuota++
					} else {
						return field.Invalid(field.NewPath("metadata", "labels"), "Custom admission Controller: Forbidden. Quota check failed", "Not enough quota available")
					}
				}
			}
			// App-Studio and BSPAIN - App Kind
			// TODO - the way we have defined our API resource schema - makes it difficult to tie the
			// request back to a field in the entitlement. Ideally: a service porovider, service link back to the
			// entitlement would make the below checks for orgs and kind vanish and we can use the link, to iterate over the
			// entitlement and tie it back to the request.
			if isPresentInArray("org/bspian", user.GetGroups()) {
				if a.GetKind().Kind == "App" {
					configuredLimit, _ := strconv.Atoi(entitlement.Spec.QuotaItems[0].Limits)
					if bspianAppStudioUsedQuota < configuredLimit {
						bspianAppStudioUsedQuota++
					} else {
						return field.Invalid(field.NewPath("metadata", "labels"), "Custom admission Controller: Forbidden. Quota check failed", "Not enough quota available")
					}
				}
			}

		}
	}

	if err != nil {
		return err
	}
	return nil
}

func NewMutatingPCustomAdmission() admission.MutationInterface {
	p := &CustomAdmission{
		Handler: admission.NewHandler(admission.Create, admission.Update),
	}

	p.SetReadyFunc(
		func() bool {
			return p.apiBindingsHasSynced()
		},
	)

	p.SetReadyFunc(
		func() bool {
			return p.apiEntitlementHasSynced()
		},
	)

	return p
}

// Ensure that the required admission interfaces are implemented.
var _ = admission.ValidationInterface(&CustomAdmission{})

func (o *CustomAdmission) Validate(ctx context.Context, a admission.Attributes, _ admission.ObjectInterfaces) (err error) {
	if a.GetResource().GroupResource() != apisv1alpha1.Resource("apibindings") {
		return nil
	}
	fmt.Println("Custom Admission Validating API Binding")

	u, ok := a.GetObject().(*unstructured.Unstructured)
	if !ok {
		return fmt.Errorf("unexpected type %T", a.GetObject())
	}
	//bspain quota

	apiBinding := &apisv1alpha1.APIBinding{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(u.Object, apiBinding); err != nil {
		return fmt.Errorf("failed to convert unstructured to APIBinding: %w", err)
	}

	if apiBinding.Spec.Reference.Workspace == nil {
		return nil
	}

	fmt.Println("check entitlement")

	// write back
	raw, err := runtime.DefaultUnstructuredConverter.ToUnstructured(apiBinding)
	if err != nil {
		return err
	}
	u.Object = raw
	return nil
}

// SetKcpInformers implements the WantsExternalKcpInformerFactory interface.
func (m *CustomAdmission) SetKcpInformers(f kcpinformers.SharedInformerFactory) {
	m.apiBindingsHasSynced = f.Apis().V1alpha1().APIBindings().Informer().HasSynced
	m.entitlementIndexer = f.Apis().V1alpha1().Entitlements().Informer().GetIndexer()
}

func (m *CustomAdmission) ValidateInitialization() error {
	if m.apiBindingsHasSynced == nil {
		return errors.New("missing apiBindingsHasSynced")
	}
	return nil
}

func (m *CustomAdmission) SetEntitlements(f kcpinformers.SharedInformerFactory) {
	m.apiEntitlementHasSynced = f.Apis().V1alpha1().Entitlements().Informer().HasSynced
}

func getTenantId(usr user.Info) string {
	for _, group := range usr.GetGroups() {
		if strings.HasPrefix(group, "org/") {
			return group[4:]
		}
	}
	return ""
}

func isPresentInArray(input string, arr []string) bool {

	for _, str := range arr {
		if input == str {
			return true
		}
	}
	return false
}
