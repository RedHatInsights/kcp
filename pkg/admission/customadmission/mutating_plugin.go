package customadmission

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"k8s.io/apiserver/pkg/authentication/user"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/admission"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/tools/cache"

	apisv1alpha1 "github.com/kcp-dev/kcp/pkg/apis/apis/v1alpha1"
	kcpinformers "github.com/kcp-dev/kcp/pkg/client/informers/externalversions"
)

const (
	PluginName = "apis.kcp.dev/CustomAdmission"
)

var aspianHACBSBindQuota = 5
var bspainAppStudioBindQuota = 5

// Register registers the reserved metadata plugin for creation and updates.
// Deletion and connect operations are not relevant as not object changes are expected here.
func Register(plugins *admission.Plugins) {
	plugins.Register(PluginName,
		func(_ io.Reader) (admission.Interface, error) {
			return NewMutatingPCustomAdmission(), nil
		})
}

// Test
var _ admission.MutationInterface = &CustomAdmission{}
var _ admission.ValidationInterface = &CustomAdmission{}
var _ admission.InitializationValidator = &CustomAdmission{}

type CustomAdmission struct {
	*admission.Handler

	metadataClient          metadata.Interface
	apiBindingsHasSynced    cache.InformerSynced
	apiEntitlementHasSynced cache.InformerSynced
}

func (o2 *CustomAdmission) Admit(ctx context.Context, a admission.Attributes, o admission.ObjectInterfaces) (err error) {
	if a.GetSubresource() != "" {
		return nil
	}

	u, ok := a.GetObject().(metav1.Object)
	if !ok {
		return fmt.Errorf("got type %T, expected metav1.Object", a.GetObject())
	}
	if !ok {
		return fmt.Errorf("got type %T, expected metav1.Object", a.GetObject())
	}
	fmt.Println(u.GetName())
	clusterName, err := genericapirequest.ClusterNameFrom(ctx)

	user := a.GetUserInfo()
	fmt.Println(user)
	user.GetGroups()

	fmt.Println(aspianHACBSBindQuota)
	fmt.Println(bspainAppStudioBindQuota)

	// HACBS and ASPIAN
	if isPresentInArray("aspian", user.GetGroups()) {
		if u.GetName() == "hacbs" {
			if aspianHACBSBindQuota == 0 {
				err = field.Invalid(field.NewPath("metadata", "labels"), "custom admission for Quota forbidden for data my domain. No quota available", fmt.Sprintf("must be %q", " No quota available"))
			}
			aspianHACBSBindQuota = aspianHACBSBindQuota - 1 //Reduce the quota by 1
		}
	}

	// App-Studio and BSPAIN
	if isPresentInArray("bspian", user.GetGroups()) {
		if u.GetName() == "appstudio" {
			if bspainAppStudioBindQuota == 0 { //No Quota available
				err = field.Invalid(field.NewPath("metadata", "labels"), "custom admission for Quota forbidden for data my domain. No quota available", fmt.Sprintf("must be %q", " No quota available"))
			}
			bspainAppStudioBindQuota = bspainAppStudioBindQuota - 1 //Reduce the quota by 1
		}
	}

	// if user.GetName() == "ben" {
	// 	err = field.Invalid(field.NewPath("metadata", "labels"), "custom admission forbidden for data my domain no entitlement present", fmt.Sprintf("must be %q", "no entitlement found "))
	// 	return err
	// }

	if err != nil {
		return err
	}
	fmt.Println(a.GetUserInfo().GetName())
	fmt.Println(a.GetUserInfo().GetGroups())
	if u.GetName() == "data.my.domain" {
		err = field.Invalid(field.NewPath("metadata", "labels"), "custom admission forbidden for data my domain no entitlement present", fmt.Sprintf("must be %q", "no entitlement found "))
		return err
	}
	fmt.Println(clusterName)

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

func getTenantId(usr user.Info) (string, error) {
	for _, group := range usr.GetGroups() {
		if strings.HasPrefix(group, "org/") {
			return group[4:], nil
		}
	}
	return "", errors.New("organization group not found")
}

func isPresentInArray(input string, arr []string) bool {

	for _, str := range arr {
		if input == str {
			return true
		}
	}
	return false
}
