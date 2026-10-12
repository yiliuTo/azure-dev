// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
// cspell:ignore BYOAKS apiserver clusterrolebindings

package provisioning

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice/v7"
	"go.yaml.in/yaml/v3"
)

type byoAKSKubeconfig struct {
	CurrentContext string `yaml:"current-context"`
	Clusters       []struct {
		Name    string `yaml:"name"`
		Cluster struct {
			Server                   string `yaml:"server"`
			CertificateAuthorityData string `yaml:"certificate-authority-data"`
		} `yaml:"cluster"`
	} `yaml:"clusters"`
	Contexts []struct {
		Name    string `yaml:"name"`
		Context struct {
			Cluster string `yaml:"cluster"`
			User    string `yaml:"user"`
		} `yaml:"context"`
	} `yaml:"contexts"`
	Users []struct {
		Name string `yaml:"name"`
		User struct {
			Token        string `yaml:"token"`
			AuthProvider struct {
				Config map[string]string `yaml:"config"`
			} `yaml:"auth-provider"`
		} `yaml:"user"`
	} `yaml:"users"`
}

type byoAKSClusterRoleBindingList struct {
	Items []struct {
		RoleRef struct {
			APIGroup string `json:"apiGroup"`
			Kind     string `json:"kind"`
			Name     string `json:"name"`
		} `json:"roleRef"`
		Subjects []struct {
			APIGroup string `json:"apiGroup"`
			Kind     string `json:"kind"`
			Name     string `json:"name"`
		} `json:"subjects"`
	} `json:"items"`
}

func (p *FoundryProvisioningProvider) checkBYOAKSNativeRBAC(
	ctx context.Context, ids *byoAKSResources, principalID string, options *arm.ClientOptions,
) error {
	client, err := armcontainerservice.NewManagedClustersClient(ids.cluster.SubscriptionID, p.credential, options)
	if err != nil {
		return fmt.Errorf("create AKS client for native Kubernetes RBAC check: %w", err)
	}
	credentials, err := client.ListClusterUserCredentials(
		ctx, ids.cluster.ResourceGroupName, ids.cluster.Name,
		&armcontainerservice.ManagedClustersClientListClusterUserCredentialsOptions{
			Format: new(armcontainerservice.FormatAzure),
		})
	if err != nil {
		return fmt.Errorf("request ephemeral AKS user credentials (requires listClusterUserCredential/action): %w", err)
	}
	if len(credentials.Kubeconfigs) == 0 || credentials.Kubeconfigs[0] == nil ||
		len(credentials.Kubeconfigs[0].Value) == 0 {
		return errors.New("AKS returned no ephemeral user kubeconfig for the native Kubernetes RBAC check")
	}
	var config byoAKSKubeconfig
	if err := yaml.Unmarshal(credentials.Kubeconfigs[0].Value, &config); err != nil {
		return fmt.Errorf("parse ephemeral AKS user kubeconfig: %w", err)
	}
	server, ca, token, audience, err := config.connection()
	if err != nil {
		return err
	}
	if token == "" {
		accessToken, err := p.credential.GetToken(ctx, policy.TokenRequestOptions{
			Scopes: []string{strings.TrimSuffix(audience, "/") + "/.default"},
		})
		if err != nil {
			return fmt.Errorf("authenticate for the Kubernetes API using the ephemeral AKS credential: %w", err)
		}
		token = accessToken.Token
	}
	bindings, err := byoAKSReadClusterRoleBindings(ctx, server, ca, token)
	if err != nil {
		return err
	}
	if !byoAKSHasClusterAdminBinding(bindings, principalID) {
		return fmt.Errorf(
			"native Kubernetes RBAC does not grant ClusterRole cluster-admin to hosting management principal %s",
			principalID)
	}
	return nil
}

func (c *byoAKSKubeconfig) connection() (server string, ca []byte, token, audience string, err error) {
	var clusterName, userName string
	for _, context := range c.Contexts {
		if context.Name == c.CurrentContext {
			clusterName, userName = context.Context.Cluster, context.Context.User
			break
		}
	}
	if clusterName == "" || userName == "" {
		return "", nil, "", "", errors.New("ephemeral AKS kubeconfig has no usable current context")
	}
	for _, cluster := range c.Clusters {
		if cluster.Name != clusterName {
			continue
		}
		server = cluster.Cluster.Server
		ca, err = base64.StdEncoding.DecodeString(cluster.Cluster.CertificateAuthorityData)
		if err != nil {
			return "", nil, "", "", errors.New("ephemeral AKS kubeconfig contains invalid certificate authority data")
		}
		break
	}
	for _, user := range c.Users {
		if user.Name == userName {
			token = user.User.Token
			audience = user.User.AuthProvider.Config["apiserver-id"]
			break
		}
	}
	parsed, parseErr := url.Parse(server)
	if parseErr != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return "", nil, "", "", errors.New("ephemeral AKS kubeconfig has no valid HTTPS API server")
	}
	if len(ca) == 0 {
		return "", nil, "", "", errors.New("ephemeral AKS kubeconfig has no certificate authority data")
	}
	if token == "" && audience == "" {
		return "", nil, "", "", errors.New(
			"ephemeral AKS kubeconfig has neither a bearer token nor an API server token audience")
	}
	return server, ca, token, audience, nil
}

func byoAKSReadClusterRoleBindings(
	ctx context.Context, server string, ca []byte, token string,
) (*byoAKSClusterRoleBindingList, error) {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, errors.New("ephemeral AKS kubeconfig contains unusable certificate authority data")
	}
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    roots,
		},
	}
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet,
		strings.TrimSuffix(server, "/")+"/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", nil)
	if err != nil {
		return nil, errors.New("construct native Kubernetes RBAC request")
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		var dnsErr *net.DNSError
		var netErr net.Error
		if errors.As(err, &dnsErr) || errors.As(err, &netErr) {
			return nil, errors.New(
				"connect to the Kubernetes API for native RBAC verification; private-cluster DNS and network " +
					"connectivity from this machine are required")
		}
		return nil, fmt.Errorf("read native Kubernetes RBAC bindings: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, response.Body)
		return nil, fmt.Errorf("read native Kubernetes RBAC bindings: Kubernetes API returned %s",
			response.Status)
	}
	var bindings byoAKSClusterRoleBindingList
	if err := json.NewDecoder(io.LimitReader(response.Body, 16<<20)).Decode(&bindings); err != nil {
		return nil, fmt.Errorf("decode native Kubernetes RBAC bindings: %w", err)
	}
	return &bindings, nil
}

func byoAKSHasClusterAdminBinding(bindings *byoAKSClusterRoleBindingList, principalID string) bool {
	for _, binding := range bindings.Items {
		if binding.RoleRef.APIGroup != "rbac.authorization.k8s.io" ||
			binding.RoleRef.Kind != "ClusterRole" || binding.RoleRef.Name != "cluster-admin" {
			continue
		}
		for _, subject := range binding.Subjects {
			if subject.Kind != "User" || subject.APIGroup != "rbac.authorization.k8s.io" {
				continue
			}
			name := strings.TrimPrefix(subject.Name, "azure:")
			if strings.EqualFold(name, principalID) {
				return true
			}
		}
	}
	return false
}
