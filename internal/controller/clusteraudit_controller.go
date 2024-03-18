/*
Copyright 2023.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logger "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	batchv1alpha1 "github.com/yolo-operator/yolo-operator/api/v1alpha1"
	"github.com/yolo-operator/yolo-operator/pkg/condition"
	"github.com/yolo-operator/yolo-operator/pkg/k8s"
	"github.com/yolo-operator/yolo-operator/pkg/model"
	"github.com/yolo-operator/yolo-operator/pkg/plugin/trivy"

	apiv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ClusterAuditReconciler reconciles a ClusterAudit object
type ClusterAuditReconciler struct {
	Model       model.K8SLLM
	ShellAccess k8s.ShellAccess
	client.Client
	Scheme *runtime.Scheme
}

//+kubebuilder:rbac:groups=llmnetes.dev,resources=clusteraudits,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=llmnetes.dev,resources=clusteraudits/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=llmnetes.dev,resources=clusteraudits/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the ClusterAudit object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.15.0/pkg/reconcile
func (r *ClusterAuditReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logger.FromContext(ctx)
	fmt.Println("ABCDE")
	log.Info("Reconciling", "resource", req.NamespacedName)

	// First, we fetch the Command object.
	var cr batchv1alpha1.ClusterAudit
	err := r.Get(ctx, req.NamespacedName, &cr)
	if err != nil {
		log.Error(err, "unable to fetch ClusterAudit object")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Second, we check if the object is being deleted, and if so, we skip.
	// TODO(a-hilaly): maybe we should leverage finalizers instead too.
	if !cr.ObjectMeta.DeletionTimestamp.IsZero() {
		log.Info("Command is deleted")
		return ctrl.Result{}, nil
	}

	// Third, we check if the command has already been processed.
	if condition.HaveSuccessfulCondition(cr.Status.Conditions) {
		log.Info("Command already processed")
		return ctrl.Result{}, nil
	}

	config, err := clientcmd.BuildConfigFromFlags("", filepath.Join(homedir.HomeDir(), ".kube", "config"))
	if err != nil {
		panic(err)
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err)
	}

	// json
	b, _ := json.Marshal(cr.Spec)
	fmt.Println(string(b))

	if cr.Spec.Type == "" {
		fmt.Println("Scanning images....")
		podsClient := clientset.CoreV1().Pods(apiv1.NamespaceDefault)
		pods, err := podsClient.List(ctx, metav1.ListOptions{})
		if err != nil {
			return reconcile.Result{}, nil
		}

		images := map[string]string{}
		for _, pod := range pods.Items {
			for _, container := range pod.Spec.Containers {
				images[container.Image] = ""
			}
		}
		results := []string{}
		fmt.Println("images", images)
		for image := range images {
			result, err := trivy.ScanImage(image)
			if err != nil {
				fmt.Println("ERROR", err.Error(), result)
				cr.Status.Conditions = append(cr.Status.Conditions, condition.NewFailedCondition(err.Error()+result, "Unable to scan image"))
				err = r.Status().Update(ctx, &cr)
				if err != nil {
					// Temporary error, let's see how this goes.
					return ctrl.Result{}, err
				}

				return ctrl.Result{}, nil
			} else {
				results = append(results, result)
			}
			break
		}

		var vr trivy.VulnerabilityReport

		err = json.Unmarshal([]byte(results[0]), &vr)
		if err != nil {
			cr.Status.Conditions = append(cr.Status.Conditions, condition.NewFailedCondition(err.Error(), "Unable to unmarshal trivy report"))
			err = r.Status().Update(ctx, &cr)
			if err != nil {
				// Temporary error, let's see how this goes.
				return ctrl.Result{}, err
			}
		}

		output, err := r.Model.RunQuery("I found these CVEs, can you summaries it for me? is there any action to do?:\n" + results[0][0:16000])
		if err != nil {
			// instead of returning an error, we update the status of the command
			// and let the controller decide what to do with it.
			log.Error(err, "unable to run query")
			cr.Status.Conditions = append(cr.Status.Conditions, condition.NewFailedCondition(err.Error(), "Unable to run query"))
		} else {
			// Query processed successfully, we can set the output and the condition
			cr.Status.Output = output
			cr.Status.Conditions = append(cr.Status.Conditions, condition.NewSuccessfulCondition("Command processed successfully"))
		}

		log.Info("Processed", "clusterAudit cve", "", "output", output)
		err = r.Status().Update(ctx, &cr)
		if err != nil {
			// Temporary error, let's see how this goes.
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	deploymentsClient := clientset.AppsV1().Deployments(apiv1.NamespaceDefault)
	podsClient := clientset.CoreV1().Pods(apiv1.NamespaceDefault)
	pods, err := podsClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return reconcile.Result{}, nil
	}

	deployments, err := deploymentsClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return reconcile.Result{}, nil
	}

	podsB, _ := json.Marshal(pods)
	deploysB, _ := json.Marshal(deployments)

	input := "Can you look at the current pods and deployments and tell me what's the problem and how can I solve it it?:"
	input += string(podsB) + "\n---\n" + string(deploysB)

	input = input[0:4097]
	// We process the command
	log.Info("Processing", "command", input)
	output, err := r.Model.RunQuery(input)
	if err != nil {
		// instead of returning an error, we update the status of the command
		// and let the controller decide what to do with it.
		log.Error(err, "unable to run query")
		cr.Status.Conditions = append(cr.Status.Conditions, condition.NewFailedCondition(err.Error(), "Unable to run query"))
	} else {
		// Query processed successfully, we can set the output and the condition
		cr.Status.Output = output
		cr.Status.Conditions = append(cr.Status.Conditions, condition.NewSuccessfulCondition("Command processed successfully"))
	}

	log.Info("Processed", "clusterAudit", input, "output", output)
	err = r.Status().Update(ctx, &cr)
	if err != nil {
		// Temporary error, let's see how this goes.
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ClusterAuditReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&batchv1alpha1.ClusterAudit{}).
		Complete(r)
}
