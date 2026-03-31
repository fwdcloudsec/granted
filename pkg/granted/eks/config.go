package eks

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/common-fate/clio"
	"github.com/fwdcloudsec/granted/pkg/granted/proxy"
	accessv1alpha1 "github.com/common-fate/sdk/gen/commonfate/access/v1alpha1"
	"github.com/fatih/color"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
)

func OpenKubeConfig() (*api.Config, string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, "", err
	}

	kubeConfigPath := filepath.Join(homeDir, ".kube", "config")

	loader := clientcmd.ClientConfigLoadingRules{
		Precedence:       []string{kubeConfigPath},
		WarnIfAllMissing: true,
		Warner: func(err error) {
			// debug log the warning if teh file does not exist
			// it will default to creating a new file
			clio.Debug(err)
		},
	}
	config, err := loader.Load()
	if err != nil {
		return nil, "", err
	}

	return config, kubeConfigPath, nil
}

func AddContextToConfig(ensureAccessOutput *proxy.EnsureAccessOutput[*accessv1alpha1.AWSEKSProxyOutput], port int) error {

	kc, kubeConfigPath, err := OpenKubeConfig()
	if err != nil {
		return err
	}

	clusterContextName := fmt.Sprintf("cf-grant-to-%s-as-%s", ensureAccessOutput.GrantOutput.EksCluster.Name, ensureAccessOutput.GrantOutput.ServiceAccountName)
	// Use the same name for the context and the cluster, so that each grant is assigned a unique entry for the cluster
	clusterName := clusterContextName

	username := ensureAccessOutput.GrantOutput.ServiceAccountName

	// remove an existing value for the context being added/updated
	delete(kc.Contexts, clusterContextName)
	// remove existing cluster definitions so they can be reset
	delete(kc.Clusters, clusterName)
	// remove existing user definitions so they can be reset
	delete(kc.AuthInfos, username)

	newCluster := api.NewCluster()
	newCluster.Server = fmt.Sprintf("http://localhost:%d", port)
	newCluster.InsecureSkipTLSVerify = true
	//add the new cluster and context back in
	kc.Clusters[clusterName] = newCluster

	newContext := api.NewContext()
	newContext.Cluster = clusterName
	newContext.AuthInfo = username
	// @TODO, teams may wish to specify a default namespace for each user or cluster?
	newContext.Namespace = "default"
	kc.Contexts[clusterContextName] = newContext

	newUser := api.NewAuthInfo()
	newUser.Impersonate = username
	kc.AuthInfos[username] = newUser

	err = clientcmd.WriteToFile(*kc, kubeConfigPath)
	if err != nil {
		return err
	}

	//set the context
	clio.Infof("EKS proxy is ready for connections")
	clio.Infof("Your `~/.kube/config` file has been updated with a new cluster context. To connect to this cluster, run the following command to switch your current context:")
	clio.Log(color.YellowString("kubectl config use-context %s", clusterContextName))
	clio.NewLine()
	clio.Infof("Or using the --context flag with kubectl: %s", color.YellowString("kubectl --context=%s", clusterContextName))
	clio.NewLine()

	return nil

}
