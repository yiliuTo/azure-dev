# Foundry Projects

<!-- cspell:ignore UAMI Kata blackhole katagen kubenet -->

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
      # Optional: omit to let azd create a dedicated registry in the Foundry resource group.
      # containerRegistryResourceId: ${AZURE_CONTAINER_REGISTRY_RESOURCE_ID}
```

The referenced cluster, agent subnet, storage account, and two user-assigned managed
identities must already exist. An optional `containerRegistryResourceId` must be
the full ARM ID of an existing Azure Container Registry and supports `${VAR}`
substitution from the azd environment. When it is omitted, azd deterministically
names, creates, records, and reuses one dedicated Premium registry in the Foundry
resource group. It never writes this resolved value back to `azure.yaml`.
The storage account must be in the same
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
the AKS AgentPool child resources, node and pod subnets, parent VNets, peerings,
and any attached route tables or NSGs. Restricted storage configurations also
require read access to the storage network policy and, when configured, its
private endpoints, private DNS zone groups, zones and VNet links. The caller needs
`Microsoft.Authorization/roleAssignments/read` and
`Microsoft.Authorization/roleAssignments/write` at the AKS cluster, workload
UAMI, storage account, and container registry scopes listed below, and
`Microsoft.Network/virtualNetworks/subnets/write` on the agent subnet.
The `roleAssignments/write` check is unconditional, even when every target
assignment already exists. The caller also needs permission to read the Foundry
resource group and registry. azd checks resource-group or registry create actions
only for a resource that is actually missing and will be created during this
run. For a future registry, azd evaluates its role-assignment and create actions
at the existing Foundry resource group, or at the subscription when that group
is also missing. It does not add a general write gate to customer-provided AKS,
VNet, UAMI, Storage, resource-group, or registry resources. azd does not elevate the caller
or grant either managed identity a network role. A denied read or required
preparation operation stops provisioning; it is not a warning that allows
Foundry creation to continue. The later ARM deployment still enforces the normal
create and write permissions for the Foundry resources it deploys.

The preflight checks:

- Foundry, AKS and storage use the same subscription and region; region comparison
  is case-insensitive. The agent subnet is in that subscription too.
- The resource is an AKS Standard cluster (not AKS Automatic or Azure Arc-enabled
  Kubernetes), runs Kubernetes 1.31 or later, uses a managed control-plane
  identity, has provisioning state `Succeeded`, and has Azure Policy enabled.
  Kubernetes 1.36.3 is the current recommendation, not an exact requirement.
- AKS has OIDC issuer and workload identity enabled. A populated issuer URL is
  not required as an additional preflight condition.
- The network is Azure CNI Overlay or Azure CNI Pod Subnet. kubenet and Azure CNI
  Node Subnet are rejected.
- azd lists and then reads each AgentPool child ARM resource directly. **One and the same pool**
  must be User mode, Linux with Azure Linux, `KataVmIsolation`, count at least
  one, have a non-empty VM size, node image
  `AKSAzureLinux-V3katagen2-202608.14.0` or later, exact label
  `agents.ai.azure.com/sandbox-node: "true"`, disabled SSH access, and
  provisioning state `Succeeded`. azd does not change the pool.
- The two managed identities are different, both have resolved `principalId`
  values, and the workload identity also has `clientId` and `tenantId`.
- AKS exposes a kubelet identity `objectId`. A provided or previously recorded
  registry is readable, fully provisioned, has a login server, and uses either
  legacy registry permissions or RBAC Registry + ABAC Repository Permissions.
  An omitted registry is reported as a resource azd will automatically prepare.
- The dedicated Foundry/Data Proxy subnet has one RFC 1918 IPv4 prefix with an
  exact `/27` mask. azd reads the node subnet referenced by every AgentPool and,
  for non-overlay networking, every referenced pod subnet. It compares their
  actual address prefixes and rejects any CIDR overlap with the agent subnet.
- When the agent and AKS subnets share a VNet, Azure system routing and
  Azure-provided DNS satisfy the routing and name-resolution prerequisites.
  Peering, custom routes, NSGs, private endpoints, and private DNS zones are not
  required merely because they exist as possible Azure networking features.
- When the subnets use separate VNets, azd requires connected, fully synchronized
  bidirectional peering that includes both selected subnets and allows VNet
  access. Azure system routes or attached UDRs must preserve the path in both
  directions; a virtual appliance path also requires forwarded traffic on the
  peerings. Both VNets must use Azure-provided DNS or share a custom DNS resolver.
- Route tables and NSGs are read only when attached. They must be in `Succeeded`
  state. azd rejects UDRs that blackhole or force the required subnet path to the
  Internet or local VNet, and rejects a higher-priority NSG rule that
  unconditionally denies every protocol and port across the required path.
- Storage with public access and ACL default `Allow` needs no private networking.
  With ACL default `Deny`, every agent, node, and non-overlay pod subnet must
  have a successful Storage service endpoint and a matching successful storage
  VNet rule. Attached NSGs are evaluated for either public path; when an NSG
  blocks that path, azd can instead accept a complete private-link path.
  Otherwise, or when public access is disabled, azd requires an approved blob
  private endpoint on a reachable subnet, a successful blob private DNS zone
  group, and a `Succeeded`/`Completed` zone link for each source VNet that uses
  Azure-provided DNS. VNets using custom DNS must share a resolver; its
  reachability and forwarding behavior are operational prerequisites described
  below.

Authorization follows the cluster's authentication configuration:

- Managed Microsoft Entra plus Azure RBAC adds Azure Kubernetes Service RBAC
  Cluster Admin (`b1ff04bb-8a4e-4dc4-8eb5-8693973ce19b`) for the hosting
  management identity at AKS scope, in addition to the four public-preview roles.
- Managed Microsoft Entra plus native Kubernetes RBAC obtains an ephemeral
  in-memory user kubeconfig, requests an in-memory bearer token, and reads
  ClusterRoleBindings to verify that the hosting management identity's Entra
  object ID is bound to ClusterRole `cluster-admin`. Nothing is written to the
  cluster or disk, and credentials, CA data and tokens are not printed. The azd
  caller needs `Microsoft.ContainerService/managedClusters/listClusterUserCredential/action`
  and Kubernetes API authorization to list ClusterRoleBindings. Private clusters
  also require working private DNS and network connectivity from the machine
  running azd. This control-plane probe originates on that machine; it does not
  demonstrate routing or DNS from the agent subnet to the node-pool or storage
  networks.
- Non-Entra authentication needs no additional Kubernetes data-plane role for
  this provisioning flow. Legacy unmanaged Entra configurations fail preflight.

The public-preview service contract always requires the following **four role
assignments across three resource scopes**:

| Identity | Scope | Role | Role definition ID |
|---|---|---|---|
| Hosting management UAMI | AKS resource | Reader | `acdd72a7-3385-48ef-bd42-f606fba81ae7` |
| Hosting management UAMI | AKS resource | Kubernetes Extension Contributor | `85cb6faf-e071-4c9b-8136-154b5a04f717` |
| Hosting management UAMI | Workload UAMI resource | Managed Identity Federated Identity Credential Contributor | `7e559ce2-48d7-4b27-9128-fa1b247f1308` |
| Workload UAMI | Storage account resource | Storage Blob Data Contributor | `ba92f5b4-2d11-453d-a403-e96b0029c9fe` |

azd reads the actual UAMI principal IDs before checking or assigning roles.
Existing unconditional assignments of these roles at the target or an inherited
scope are reused; a blob-container-only assignment does not satisfy the storage
account scope. No role is newly assigned at subscription scope. The workload
identity receives no AKS management permission.

Container image pulls add exactly one separate assignment for the AKS kubelet
identity, using its `objectId` as the assignment principal:

| Registry permission mode | Scope | Role | Role definition ID |
|---|---|---|---|
| Legacy/RBAC Registry Permissions | Container registry resource | AcrPull | `7f951dda-4ed3-4680-a7ca-43fe172d538d` |
| RBAC Registry + ABAC Repository Permissions | Container registry resource | Container Registry Repository Reader | `cfdd1b31-da27-4c57-8c4d-79c61a2f2427` |

azd selects only the role matching the registry mode. An existing unconditional
exact or inherited assignment is reused. An assignment with a condition is not
treated as equivalent because azd cannot assume that its condition permits the
required image pull.

The preflight runs exactly once and finishes before azd creates or changes any
resource. It reports each prerequisite as satisfied, automatically preparable,
or an error that cannot be repaired automatically. After it passes, preparation
creates a missing Foundry resource group without changing tags on an existing
group, creates a missing dedicated registry, and then applies the planned role
assignments and subnet delegation. Preparation consumes that plan; completion
polling and read-back do not rerun preflight. The main Foundry deployment uses
the same prepared registry and does not create or retag the resource group.

The prepared registry ID, login server, and lifecycle mode are recorded through
the existing `AZURE_CONTAINER_REGISTRY_RESOURCE_ID`,
`AZURE_CONTAINER_REGISTRY_ENDPOINT`, and `AZD_FOUNDRY_ACR_MODE` outputs. A
provided registry is connected to the Foundry project instead of creating a
second registry. The Foundry project identity receives the registry
mode-appropriate read role through the existing connection flow.

If the agent subnet has no delegation, azd adds `Microsoft.App/environments`,
retaining the other returned subnet properties, including NSG, route table, NAT
gateway and service endpoints. It does not edit VNet DNS, change address ranges,
touch AKS node/pod subnets, remove conflicting delegations or enable multiple
delegations. An existing different delegation fails preflight. azd does not
create or modify peering, routes, NSGs, private endpoints, private DNS, or storage
network rules. The planned scopes, principals and changes are displayed before
preparation starts. Registry creation, role assignments, and delegation are
idempotent.
Federated identity credentials and trusted access are not pre-created; the
Foundry service owns its workload federation setup. azd does not add a separate
Microsoft Graph or federated-identity tenant-policy gate; a later service or
Graph failure is preserved with its Azure error and remediation context.

Agent-image private trusted-root validation is intentionally outside this
account/project preflight because the agent image digest is not yet known. It
must be enforced later in the agent-image lifecycle when that digest is
available; passing this preflight is not an attestation that private roots were
validated.

Upgrading from an earlier demo build is non-destructive. azd stops checking and
creating AKS Contributor and Foundry resource-group Reader assignments. AKS RBAC
Cluster Admin is now checked or created only for managed Entra clusters using
Azure RBAC. azd does not remove any existing customer-owned assignment. Review
and remove obsolete assignments separately only after confirming they are no
longer required.

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

To reuse an existing registry, uncomment `containerRegistryResourceId` in the
service configuration and set `AZURE_CONTAINER_REGISTRY_RESOURCE_ID` to its full
ARM resource ID before provisioning. Otherwise, leave the field absent.

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

The network checks prove the ARM configuration prerequisites described above;
they do not originate packets from the agent subnet. They therefore cannot prove
that a custom DNS resolver is reachable or forwards the required private zones,
that a virtual appliance forwards traffic, that narrower protocol- or
port-specific NSG rules permit a service's undocumented traffic, or that Storage
data-plane requests succeed. Validate those operational behaviors with workloads
before production.
The checks also do not prove available subnet capacity or that a new role
assignment is already effective. RBAC propagation can cause the immediate
Foundry request to fail even after preparation succeeds. The service error is
preserved. Diagnose persistent authorization failures rather than repeatedly
retrying or assuming a fixed sleep proves readiness. Successful preparation is
retained after later failures and is reused on retry. `azd down` does not undo
these changes to customer-owned identities, AKS, storage, a provided registry,
or the agent subnet.

**Historical pre-public-preview validation results (2026-09-29 and 2026-09-30,
West US 2):**

| Scenario | Observed result |
|---|---|
| Missing sandbox label | Native `azd provision` failed preflight. Cloud checks confirmed no role assignments, subnet delegation or Foundry resources were created. |
| Corrected sandbox label with the earlier build | Native `azd provision` created six assignments, including Reader on AKS instead of the Foundry resource group, and added the agent subnet delegation before submitting the Foundry deployment. |
| Repeated provisioning with the earlier build | Existing assignments and delegation were reused. All six assignment IDs, creation/update timestamps and the subnet ETag remained unchanged across the first two attempts. |
| Foundry account and project with the earlier build | Three attempts reached `Failed` with the Trusted Access authorization error below, and the project list remained empty. |
| External Reader correction | After a user separately added Reader for the hosting management identity on the Foundry resource group, one subsequent native `azd provision` completed and the account, project and Trusted Access binding reached `Succeeded`. The original 403 did not expose its denied action or scope, so this sequence does not prove that Reader was the only changed input or the unique cause. |

**Historical six-role corrected-build validation (2026-10-08, West US 2):**

A fresh hosting management identity started with no role assignments, and the
dedicated Foundry resource group did not exist. Native `azd provision` passed
the read-only preflight, created the Foundry resource group, assigned the three
AKS roles without assigning AKS Reader, assigned Foundry resource-group Reader
and workload-UAMI FIC Contributor, and reused the existing storage role and
subnet delegation. The subnet ETag remained unchanged.

The Foundry deployment was then rejected during service validation because the
reused AKS cluster was already bound to another Foundry account in the
subscription. No Foundry resource was created in the new group. Reaching an
independent corrected-build account/project/Trusted Access success would require
either removing that existing binding or provisioning another qualified AKS
cluster, so neither destructive workaround nor a second deterministic retry was
performed. The corrected role scope and fresh-resource-group ordering are
verified; corrected-build end-to-end Foundry success is not.

Three native provisioning attempts returned the same error:

> The hosting-management identity is not authorized to manage Trusted Access bindings on the configured AKS cluster.

The final attempt started 24 minutes after the initial role assignments. Neither
elapsed time nor visible assignments proves that authorization is effective.
Likewise, an account appearing in a resource list does not mean its provisioning
state is `Succeeded`. This error alone does not establish RBAC propagation or
preview enrollment as the cause.

**Public-preview contract validation (2026-10-08, West Central US):**

A fresh AKS 1.35 cluster with Azure CNI Overlay, OIDC, workload identity, Azure
RBAC, and a labeled Kata pool was validated through native `azd provision`.
With the sandbox label removed, preflight failed before creating assignments,
subnet delegation, or the Foundry resource group. After restoring the label,
azd created exactly the four hosting/workload assignments documented above
(before the kubelet registry-role preparation described in this revision),
delegated the agent
subnet, and the Foundry account, project, and Trusted Access binding all reached
`Succeeded`. The hosting identity had neither AKS Contributor nor AKS RBAC
Cluster Admin on the cluster and had no Reader assignment on the Foundry
resource group. A second provision reused all assignment IDs and timestamps and
left the subnet ETag unchanged.

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
