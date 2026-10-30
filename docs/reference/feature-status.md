# Feature Status

Current maturity status of Azure Developer CLI features. See [Feature Stages](../concepts/feature-stages.md) for what each stage means.

## Commands

| Feature | Stage |
|---|---|
| `add` | Beta |
| `auth` | Stable |
| `config` | Stable |
| `deploy` | Stable |
| `down` | Stable |
| `env` | Stable |
| `env unset` | Beta |
| `help` | Stable |
| `infra generate` | Beta |
| `init` | Stable |
| `monitor` | Beta |
| `package` | Beta |
| `pipeline` | Beta |
| `provision` | Stable |
| `restore` | Beta |
| `show` | Stable |
| `template` | Beta |
| `up` | Stable |
| `update` | Beta |
| `version` | Stable |

## Languages

| Language | Stage |
|---|---|
| Python | Stable |
| JavaScript / TypeScript | Stable |
| Java | Stable |
| .NET (C#) | Stable |

## Infrastructure as Code

| Provider | Stage |
|---|---|
| Bicep | Stable |
| Terraform | Beta |

## Hosting Targets

| Host | Stage |
|---|---|
| Azure App Service | Stable |
| Azure Static Web Apps | Stable |
| Azure Container Apps | Stable |
| Azure Functions | Stable |
| Azure Kubernetes Service (AKS) | Beta |
| Azure AI | Beta |

## Clients

| Client | Stage |
|---|---|
| VS Code Extension | Beta |
| Codespaces | Beta |
| Cloud Shell | Beta |
| Visual Studio | Alpha |

## CI/CD

| Platform | Stage |
|---|---|
| GitHub Actions | Stable |
| Azure Pipelines | Stable |

## Advanced Features

| Feature | Stage |
|---|---|
| Resource Group Deployments | Beta |
| Layered Provisioning | Beta |
| Deployment Preview (`deploy --preview`) | Beta |
| Deployment Stacks | Alpha |
| Extensions | Stable |
| [Projects BYO-AKS simplified onboarding](../../cli/azd/extensions/azure.ai.projects/README.md#host-agents-on-a-customer-owned-aks-cluster) | In development; requires explicit standard `network.agentSubnet` and `network.peSubnet` in an existing VNet, with private routing/DNS for Foundry access; missing/non-subnet injection fails before Azure writes; read-only preflight and one ARM deployment for dependencies, hosting and grants; independently optional supplied hosting/workload UAMIs, four-resource preflight progress and targeted interrupted-grant recovery; completion uses ARM results without post-ARM readiness gates; `azd down` deletes the entire explicit target resource group; P02-P05 check basic Actions/NotActions allow for actual selected operations, without nonexistent AKS/VNet writes; P06 checks ordinary unconditional authority for selected G01-G03 writes; N02 applies only to existing Agent subnets selected through standard `network.agentSubnet` and validates basic resource metadata/readiness, private CIDR capacity, parent-VNet containment, non-overlap with the selected AKS pool's Node subnet and delegation, not routing, DNS or connectivity; N01 deferred pending a future service-owned Storage FQDN contract; S03 validates the supplied-Storage public baseline and skips restricted/private network verification without blocking |

## Extension gRPC Contracts

| Capability | Contract stage | Stable since | Beta status |
|---|---|---|---|
| Extension usage telemetry (`TelemetryService.ReportUsage`) | Stable v1 | azd 1.36.0 | Deprecated; wire route retained |
| Current Azure principal (`AccountService.GetCurrentPrincipal`) | Stable v1 | azd 1.36.0 | Deprecated; wire route retained |
| Deployment preview (`ServiceTargetService.Stream`) | Stable v1 | azd 1.37.0 | Preview messages/fields deprecated; wire route and Go SDK compatibility retained |

The deployment preview contract graduation does not change the CLI feature stage
in Advanced Features above. Host and SDK 1.37.0 shipped on October 21, 2026; see the
[second graduation audit](https://github.com/Azure/azure-dev/issues/10625).

These are contract graduations, not a change to the overall Extensions feature stage
or telemetry eligibility/privacy policy. The minimum azd runtime version for stable
consumers depends on the capabilities they use:

- Extension usage telemetry or current Azure principal: `requiredAzdVersion: ">=1.36.0"`.
- Deployment preview: `requiredAzdVersion: ">=1.37.0"`.

Extensions using multiple capabilities must meet the highest applicable minimum and
retain any stricter existing requirement.

`requiredAzdVersion` constrains the azd runtime version, not the Go SDK dependency.
Pin the SDK separately to a published module release containing the stable APIs in use.
See [contract lifecycle and SDK migration](../../cli/azd/docs/extensions/contract-versioning.md).

---

For the full feature tracking table, see [cli/azd/docs/feature-stages.md](../../cli/azd/docs/feature-stages.md).
