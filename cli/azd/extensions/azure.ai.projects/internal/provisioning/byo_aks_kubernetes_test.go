// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package provisioning

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBYOAKSKubeconfigConnection(t *testing.T) {
	config := byoAKSKubeconfig{CurrentContext: "current"}
	config.Contexts = append(config.Contexts, struct {
		Name    string `yaml:"name"`
		Context struct {
			Cluster string `yaml:"cluster"`
			User    string `yaml:"user"`
		} `yaml:"context"`
	}{Name: "current"})
	config.Contexts[0].Context.Cluster = "cluster"
	config.Contexts[0].Context.User = "user"
	config.Clusters = append(config.Clusters, struct {
		Name    string `yaml:"name"`
		Cluster struct {
			Server                   string `yaml:"server"`
			CertificateAuthorityData string `yaml:"certificate-authority-data"`
		} `yaml:"cluster"`
	}{Name: "cluster"})
	config.Clusters[0].Cluster.Server = "https://private.example"
	config.Clusters[0].Cluster.CertificateAuthorityData =
		base64.StdEncoding.EncodeToString([]byte("test-ca"))
	config.Users = append(config.Users, struct {
		Name string `yaml:"name"`
		User struct {
			Token        string `yaml:"token"`
			AuthProvider struct {
				Config map[string]string `yaml:"config"`
			} `yaml:"auth-provider"`
		} `yaml:"user"`
	}{Name: "user"})
	config.Users[0].User.AuthProvider.Config = map[string]string{
		"apiserver-id": "sovereign-cloud-server-application",
	}

	server, ca, token, audience, err := config.connection()
	require.NoError(t, err)
	assert.Equal(t, "https://private.example", server)
	assert.Equal(t, []byte("test-ca"), ca)
	assert.Empty(t, token)
	assert.Equal(t, "sovereign-cloud-server-application", audience)
}

func TestBYOAKSHasClusterAdminBinding(t *testing.T) {
	binding := func(role, kind, subject string) *byoAKSClusterRoleBindingList {
		var result byoAKSClusterRoleBindingList
		item := struct {
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
		}{}
		item.RoleRef.APIGroup = "rbac.authorization.k8s.io"
		item.RoleRef.Kind = "ClusterRole"
		item.RoleRef.Name = role
		item.Subjects = append(item.Subjects, struct {
			APIGroup string `json:"apiGroup"`
			Kind     string `json:"kind"`
			Name     string `json:"name"`
		}{APIGroup: "rbac.authorization.k8s.io", Kind: kind, Name: subject})
		result.Items = append(result.Items, item)
		return &result
	}
	for _, tt := range []struct {
		name, role, kind, subject string
		valid                     bool
	}{
		{"object ID", "cluster-admin", "User", byoTestManagementID, true},
		{"Azure-prefixed object ID", "cluster-admin", "User", "azure:" + byoTestManagementID, true},
		{"case-insensitive object ID", "cluster-admin", "User", strings.ToUpper(byoTestManagementID), true},
		{"wrong subject", "cluster-admin", "User", byoTestWorkloadID, false},
		{"wrong role", "view", "User", byoTestManagementID, false},
		{"group is not the identity", "cluster-admin", "Group", byoTestManagementID, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.valid,
				byoAKSHasClusterAdminBinding(binding(tt.role, tt.kind, tt.subject), byoTestManagementID))
		})
	}
}

func TestBYOAKSReadClusterRoleBindings(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", r.URL.Path)
		assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[]}`))
	}))
	defer server.Close()
	certificate, err := x509.ParseCertificate(server.TLS.Certificates[0].Certificate[0])
	require.NoError(t, err)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})

	bindings, err := byoAKSReadClusterRoleBindings(t.Context(), server.URL, ca, "test-token")
	require.NoError(t, err)
	assert.Empty(t, bindings.Items)
}

func TestBYOAKSReadClusterRoleBindingsErrors(t *testing.T) {
	t.Run("API authorization", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "secret body must not be surfaced", http.StatusForbidden)
		}))
		defer server.Close()
		certificate, err := x509.ParseCertificate(server.TLS.Certificates[0].Certificate[0])
		require.NoError(t, err)
		ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
		_, err = byoAKSReadClusterRoleBindings(t.Context(), server.URL, ca, "secret-token")
		require.ErrorContains(t, err, "403 Forbidden")
		assert.NotContains(t, err.Error(), "secret")
	})
	t.Run("private cluster network", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		certificate, parseErr := x509.ParseCertificate(server.TLS.Certificates[0].Certificate[0])
		require.NoError(t, parseErr)
		ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
		url := server.URL
		server.Close()
		_, err := byoAKSReadClusterRoleBindings(context.Background(), url, ca, "secret-token")
		require.ErrorContains(t, err, "private-cluster DNS and network connectivity")
		assert.NotContains(t, err.Error(), "secret-token")
	})
}
