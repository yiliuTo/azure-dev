# Foundry Projects

Manage Microsoft Foundry Project resources from your terminal. (Preview)

See the shared [AI extension non-interactive input reference](../ai-non-interactive.md)
for every prompt's flag, environment/configuration input, or deterministic
no-prompt behavior.

## `azure.yaml` ownership

This extension owns `host: azure.ai.project` services and the `microsoft.foundry` provisioning provider. A project service carries account-level settings such as an existing project endpoint, model deployments, and private networking.

```yaml
infra:
  provider: microsoft.foundry

services:
  my-project:
    host: azure.ai.project
    endpoint: https://my-account.services.ai.azure.com/api/projects/my-project
    deployments:
      - name: gpt-4.1-mini
        model:
          format: OpenAI
          name: gpt-4.1-mini
          version: "2025-04-14"
        sku:
          name: GlobalStandard
          capacity: 50
```

When `endpoint` is omitted, `azd provision` creates a Foundry account and project. When it is set, provisioning reuses that project and reconciles the declarations that can be applied to an existing account.

### Host agents on a customer-owned AKS cluster

For a newly created Foundry account, set `agentHosting` on the `azure.ai.project`
service:

```yaml
infra:
  provider: microsoft.foundry

services:
  my-project:
    host: azure.ai.project
    agentHosting:
      hostingType: ManagedCluster
      name: primary
      clusterResourceId: ${AZURE_AKS_CLUSTER_ID}
      agentSubnetResourceId: ${AZURE_AGENT_SUBNET_ID}
      hostingManagementIdentityResourceId: ${AZURE_HOSTING_MANAGEMENT_IDENTITY_ID}
      storageAccountResourceId: ${AZURE_HOSTED_AGENTS_STORAGE_ID}
      workloadIdentityResourceId: ${AZURE_HOSTED_AGENTS_WORKLOAD_IDENTITY_ID}
```

The referenced cluster, agent subnet, storage account, and two user-assigned managed
identities must already exist. The storage account must be in the same
subscription and region as the AKS cluster, and its data-plane endpoint must be
reachable from the workload network. The hosting management identity is
attached to the Foundry account automatically.

Foundry agent hosting configuration is fixed when the account is created. It
cannot be added to an existing account or changed after creation, so
`agentHosting` cannot be used together with `endpoint`.

#### Automatic preparation in this demo branch

With this branch's `azure.ai.projects` extension installed, the configuration
above makes native `azd provision` perform a read-only BYO AKS preflight, prepare
missing role assignments and the agent subnet delegation, and only then submit
the Foundry ARM deployment. There is no additional flag or environment switch.
Projects without `agentHosting` keep their existing behavior.

All requests use the identity logged in through `azd auth login`, not either
managed identity. The caller needs read access to the referenced resources and
their role assignments, `Microsoft.Authorization/roleAssignments/write` at the
three resource scopes listed below, and
`Microsoft.Network/virtualNetworks/subnets/write` on the agent subnet.
The caller also needs the usual permission to provision the Foundry resource
group and its resources. azd does not elevate the caller or grant either managed
identity a network role. A denied read or required preparation operation stops
provisioning; it is not a warning that allows Foundry creation to continue.

The preflight checks:

- Foundry, AKS and storage use the same subscription and region; region comparison
  is case-insensitive. The agent subnet is in that subscription too.
- AKS has an enabled OIDC issuer with a non-empty issuer URL, and workload identity
  is enabled.
- The network plugin is Azure CNI, with overlay mode or a non-null `podSubnetID`
  on **every** node pool.
- **One and the same pool** has `workloadRuntime: KataVmIsolation`
  (case-insensitive) and the label `agents.ai.azure.com/sandbox-node: "true"`
  (case-sensitive). azd does not add this label or change the cluster.
- The two managed identities are different, both have resolved `principalId`
  values, and the workload identity also has `clientId` and `tenantId`.
- The dedicated Foundry/Data Proxy subnet is different from every AKS node and pod
  subnet. For this demo, it must be in the same VNet as the node subnets, and AKS
  must have `aadProfile.enableAzureRBAC: true`. Cross-VNet preparation and native
  Kubernetes RBAC bindings are **demo limitations**, not general BYO AKS product
  restrictions.
- The agent subnet has an IPv4 address prefix beginning with 10, 172 or 192,
  using `addressPrefix` or the first `addressPrefixes` entry. This demo does not
  impose a `/27` minimum, Kubernetes version, node count, VM SKU, OS or Ready-state
  requirement.

The service chooses its hosting backend. To accommodate both the Kubernetes
extension and Helm backends, this demo prepares the following **union of six
resource-scoped roles**. This is not a claim that every backend requires all six.

| Identity | Scope | Role | Role definition ID |
|---|---|---|---|
| Hosting management UAMI | AKS resource | Azure Kubernetes Service Contributor Role | `ed7f3fbd-7b88-4dd4-9017-9adb7ce333f8` |
| Hosting management UAMI | AKS resource | Azure Kubernetes Service RBAC Cluster Admin | `b1ff04bb-8a4e-4dc4-8eb5-8693973ce19b` |
| Hosting management UAMI | AKS resource | Kubernetes Extension Contributor | `85cb6faf-e071-4c9b-8136-154b5a04f717` |
| Hosting management UAMI | AKS resource | Reader | `acdd72a7-3385-48ef-bd42-f606fba81ae7` |
| Hosting management UAMI | Workload UAMI resource | Managed Identity Federated Identity Credential Contributor | `7e559ce2-48d7-4b27-9128-fa1b247f1308` |
| Workload UAMI | Storage account resource | Storage Blob Data Contributor | `ba92f5b4-2d11-453d-a403-e96b0029c9fe` |

azd reads the actual UAMI principal IDs before checking or assigning roles.
Existing unconditional assignments of these roles at the target or an inherited
scope are reused; a blob-container-only assignment does not satisfy the storage
account scope. No role is newly assigned at resource-group or subscription scope.
The workload identity receives no AKS management permission.

If the agent subnet has no delegation, azd adds `Microsoft.App/environments`,
retaining the other returned subnet properties, including NSG, route table, NAT
gateway and service endpoints. It does not edit VNet DNS, change address ranges,
touch AKS node/pod subnets, remove conflicting delegations or enable multiple
delegations. The planned scopes, principals and changes are displayed before
preparation starts. Both the role assignments and delegation are idempotent.
Federated identity credentials and trusted access are not pre-created; the
Foundry service owns its workload federation setup.

After saving the `azure.yaml` above in a new project directory, supply the
existing resource IDs and an explicit, dedicated Foundry resource group:

```sh
azd auth login
azd env new byo-aks-demo
azd env set AZURE_SUBSCRIPTION_ID "<subscription-id>"
azd env set AZURE_LOCATION "<aks-region>"
azd env set AZURE_RESOURCE_GROUP "<dedicated-foundry-resource-group>"
azd env set AZURE_AKS_CLUSTER_ID "<aks-resource-id>"
azd env set AZURE_AGENT_SUBNET_ID "<dedicated-agent-subnet-resource-id>"
azd env set AZURE_HOSTING_MANAGEMENT_IDENTITY_ID "<management-uami-resource-id>"
azd env set AZURE_HOSTED_AGENTS_WORKLOAD_IDENTITY_ID "<workload-uami-resource-id>"
azd env set AZURE_HOSTED_AGENTS_STORAGE_ID "<storage-account-resource-id>"
azd provision
```

The root `infra.provider: microsoft.foundry` path reads `AZURE_RESOURCE_GROUP`;
`AZURE_FOUNDRY_RESOURCE_GROUP` is for a named Foundry infrastructure layer, not a
replacement for the root setting. Once all existing inputs are set,
`azd provision --no-prompt` runs the same preparation without an extra consent
prompt. Only run it with resource IDs and scopes you are authorized to prepare.

To demonstrate fail-fast behavior, first run with the sandbox label missing.
The error identifies the cluster, the failed property, the observed state and
the expected state, with remediation. No prerequisite mutation or Foundry
deployment is submitted. Correct the label on the Kata pool, then rerun the same
`azd provision` command to exercise preparation and attempt Foundry creation.

**Boundaries:** this demo supports only new accounts using the embedded
`microsoft.foundry` template. Deploying BYO AKS with ejected Bicep is rejected;
Terraform bypasses this provider and receives neither its preflight nor its
automatic preparation. Initialize and Preview never apply preparation.
This is a client-side check for this azd path, not a service-wide implementation
of preflight across Portal, other CLIs or direct ARM callers.

The checks do not prove storage data-plane reachability, available subnet
capacity, or that a new role assignment is already effective. RBAC propagation
can cause the immediate Foundry request to fail even after preparation succeeds.
The service error is preserved. Diagnose persistent authorization failures
rather than repeatedly retrying or assuming a fixed sleep proves readiness.
Successful preparation is retained after later failures and is reused on retry.
`azd down` does not undo these changes to customer-owned identities, AKS, storage
or the agent subnet.

**Live validation results (2026-09-29, West US 2):**

| Scenario | Observed result |
|---|---|
| Missing sandbox label | Native `azd provision` failed preflight. Cloud checks confirmed no role assignments, subnet delegation or Foundry resources were created. |
| Corrected sandbox label | Native `azd provision` created the six resource-scoped roles listed above and the agent subnet delegation before submitting the Foundry deployment. |
| Repeated provisioning | Existing roles and delegation were reused. All six assignment IDs, creation/update timestamps and the subnet ETag remained unchanged across the first two attempts. |
| Foundry account and project | The account reached `Failed` with a service-side Trusted Access authorization error (403), and the project list was empty. End-to-end account/project success remains unverified. |

Three native provisioning attempts returned the same error:

> The hosting-management identity is not authorized to manage Trusted Access bindings on the configured AKS cluster.

The final attempt started 24 minutes after the initial role assignments. Neither
elapsed time nor visible assignments proves that authorization is effective.
Likewise, an account appearing in a resource list does not mean its provisioning
state is `Succeeded`. This error alone does not establish RBAC propagation or
preview enrollment as the cause.

For reproduction and diagnosis, retain the sanitized nested deployment error,
failure time in UTC, and azd/extension versions. Obtain the original provider
`ErrorCode`, denied action and scope, and request/correlation IDs for the failing
operation. If only the wrapped error is exposed, request those details from the
service owner through an approved support channel before changing permissions.
Do not broaden role scopes or bypass service checks based on this message alone.

To reconcile deployments, connections, or a pending container registry on an existing project, set the project's full ARM resource ID in the active azd environment:

```sh
azd env set AZURE_AI_PROJECT_ID "/subscriptions/<subscription-id>/resourceGroups/<resource-group>/providers/Microsoft.CognitiveServices/accounts/<account>/projects/<project>"
```

`azd ai agent init` sets this value when initialized against an existing project. An endpoint-only service with no resources to reconcile does not require it.

When provisioning reports insufficient Cognitive Services quota, check usage for the target region with
`az cognitiveservices usage list --location <region>` or request a quota increase in the Azure portal. If an
existing Foundry project should be reused instead, configure its endpoint and set `AZURE_AI_PROJECT_ID` to the
full project resource ID before retrying.

The `azd ai project set`, `show`, and `unset` commands manage the default Foundry project endpoint context. They do not currently author the project service in `azure.yaml`.
