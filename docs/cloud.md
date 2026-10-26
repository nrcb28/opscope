# Read-only cloud collection

Opscope has a closed registry of eleven optional providers: `azure`, `aws`, `gcp`, `oci`, `digitalocean`, `hetzner`, `cloudflare`, `openstack`, `alibaba`, `ibm` and `scaleway`. `opscope cloud catalog` reads only local descriptors; it does not discover credentials or contact a provider. `cloud catalog --provider gcp` limits the output to one adapter. Each descriptor lists actual callable operations, resource types, permission prerequisites and experimental status. The nine new adapters are experimental and expose deliberately limited evidence.

The core collector, offline analysis, reports, bundles and UI work without cloud accounts. Cloud operations use fixed command arrays or fixed HTTPS API routes. They do not start login, fetch secret values, install extensions, enable cloud services, run commands on machines, patch resources or change infrastructure. A registered provider is not proof that an authenticated scope is configured or reachable.

## Provider setup and actual coverage

Configure credentials outside Opscope. Keep tokens in the existing CLI session or the named server-side environment variable; the browser has no credential, endpoint or arbitrary-scope form. `--endpoint` is a notification option and never selects a cloud provider endpoint.

| Provider | Operations | Scope and existing authentication | Evidence and minimum read access |
| --- | --- | --- | --- |
| Azure | `inventory`, `posture`, `health`, `vm`, `bundle`, `drift`, `patches`, `cost`, `arc`, `metadata` | Azure CLI; `--subscription` / `--subscriptions` | Existing Resource Graph/Compute/Monitor/Health/Defender/Update Manager data. Start with Reader/Monitoring Reader and verify each service permission. Resource Graph extension must already be installed. |
| AWS | `inventory`, `posture`, `health`, `instance`, `bundle`, `drift`, `patches`, `cost`, `metadata` | AWS CLI v2; `--profile` / `--profiles`, `--region` / `--regions` | Existing EC2, S3, CloudWatch, Health, SSM and security findings. See the [action-level example](cloud-readonly-iam.json); optional sources may require more access. |
| Google Cloud | `inventory`, `health`, `posture`, `metrics`, `vm`, `bundle` | Existing `gcloud` session; explicit `--project` / `--projects`, optional `--region` | Selected Asset Search resources, Compute instance state, ingress firewall configuration and optional Monitoring CPU series. `cloudasset.assets.searchAllResources`, `compute.instances.list`, `compute.firewalls.list` and Monitoring Viewer as required by the selected operation. |
| Oracle Cloud | `inventory`, `health`, `posture` | Existing OCI CLI profile; `--compartment <ocid> --region <region>`, optional `--profile` | Selected Compute instance state and network configuration; inspect/read privileges in the selected compartment. |
| DigitalOcean | `inventory`, `health`, `posture`, `metrics` | `DIGITALOCEAN_ACCESS_TOKEN`; explicit `--project <uuid>` | Project resources, associated droplets/volumes, selected firewalls and native CPU counter series. Use a read-only token with project/resource, firewall and Monitoring read access for the requested operation. |
| Hetzner Cloud | `inventory`, `health`, `posture`, `metrics` | `HCLOUD_TOKEN`; explicit `--project <local-label>` matching the token's project | Token-scoped Cloud servers, selected network configuration and provider CPU history. Use a read-only project token. The label is not independent proof of the token's project identity. |
| Cloudflare | `inventory`, `health`, `posture` | `CLOUDFLARE_API_TOKEN`; `--account <32-hex-id>` | Zone metadata, reported zone state and paused-zone configuration only. Use Zone:Read with resource restrictions. Zone state does not prove DNS/HTTP availability, WAF posture or edge analytics coverage. |
| OpenStack | `inventory`, `health`, `posture` | Existing OpenStack CLI `clouds.yaml`; `--cloud-name <entry> --project <id> --region <name>` | Selected project servers and security group rules using a reader identity. The endpoint comes from the administrator's existing CLI configuration. |
| Alibaba Cloud | `inventory`, `health`, `posture` | Existing Alibaba CLI profile; `--account <id> --region <name>`, optional `--profile` | Selected ECS instances, disks and VPCs with reported instance state; posture only checks explicit disk-encryption metadata. Grant only the used Describe/identity read calls; no guest or application health is inferred. |
| IBM Cloud | `inventory`, `health` | Externally refreshed `IBM_CLOUD_IAM_TOKEN`; explicit `--account <id> --resource-group <id> --region <name>` | Resource Controller service-instance metadata and reported state, checked against the selected account and resource-group IDs and filtered by region. Grant read access to those service instances. This adapter does not query VPC infrastructure. |
| Scaleway | `inventory`, `health` | `SCW_SECRET_KEY`; explicit `--project <uuid> --zone <name>` | Selected Instance servers, volumes and reported state. Grant Instance read access in that project/zone. |

The catalog is authoritative if this table and an older command example differ. Experimental adapters do not advertise unsupported billing, patch compliance or metric operations. `RUNNING`, `active`, zone state, a configuration rule or an empty response does not establish application availability or complete security coverage. Coverage includes source, freshness, warnings and an explicit state; missing data is not converted to a zero metric.

Google Cloud inventory includes selected Compute, GKE, Cloud SQL, Cloud Run and Storage **asset metadata**. It does not implement service-specific health for all of these products. SCC findings, OS Config patch evidence, billing exports and Google Cloud baseline drift are unavailable in this adapter. No BigQuery job is created. Cloud Monitoring uses separately configured Application Default Credentials (ADC) and `monitoring.timeSeries.list`/Monitoring Viewer. The existing `gcloud` CLI session does not itself configure ADC. Configure ADC outside Opscope using your organization's workload identity or supported local ADC workflow; no login starts from the app. Tokens stay in the backend authentication flow and are never printed, persisted by Opscope or exposed to the browser. CPU samples use a fixed fifteen-minute window and sixty-second mean alignment; no five-second cloud precision is implied. Missing ADC or Monitoring access is explicit partial/not-configured coverage, while the independent inventory/state reads remain usable. A `gcp vm`/bundle local snapshot remains separate unless an independently supported identity check establishes the same resource; Google Cloud metadata linking is not implemented.

Cloud metric histories are provider observations, separate from the five-second host sampler. Hetzner CPU history requests a sixty-second step over the preceding hour, caps reads at ten enumerated servers and retains the provider's returned period, unit and timestamps. A provider response with no metric points remains `no_data`; it does not generate a zero series. DigitalOcean CPU history keeps the provider's cumulative CPU seconds per CPU/mode over the preceding hour for at most ten project-allowlisted droplets. It does not label those cumulative counters as an instantaneous CPU percentage. Other experimental adapters do not yet expose metric histories. The UI never mixes these samples into a host CPU/RAM line.

## Configure the local Cloud workspace

The server binds providers, operations and scopes before printing the session URL. For example:

```sh
opscope serve --cloud azure,aws,gcp --subscriptions <subscription-id> --profiles audit --gcp-projects <project-id> --regions eu-west-1
opscope serve --cloud digitalocean --digitalocean-projects <project-uuid>
opscope serve --cloud openstack --cloud-name production-reader --openstack-projects <project-id> --region RegionOne
```

A session accepts at most eleven distinct providers and twenty total scope choices. New adapters require an explicit scope. The browser receives anonymous labels such as `gcp-scope-1`, never a free-form scope selector. Provider-specific allowlist options prevent a Google Cloud project ID being reused as a DigitalOcean project: `--gcp-projects`, `--digitalocean-projects`, `--hetzner-projects`, `--openstack-projects`, `--scaleway-projects`, `--oci-compartments`, `--cloudflare-accounts`, `--alibaba-accounts` and `--ibm-accounts`. Generic `--projects`, `--compartments` or `--accounts` can be used when their scope type is shared intentionally. Region/profile/token context remains fixed for the session; use separate sessions when providers require different values for the same option.

Only advertised read actions without an additional resource/baseline workflow are exposed in the workspace. VM/instance, bundle, drift, Arc and identity metadata commands remain explicit CLI workflows. Changing a provider in the UI cannot discover new accounts, install credentials or expand the server allowlist.

CLI executables must come from trusted installation locations, not the working directory or an arbitrary PATH entry. On Unix use the supported root-owned system/vendor locations (for example `/usr/bin`, `/usr/local/bin`, or the documented vendor `/opt` directory). On Windows the additional provider CLI executables use `%ProgramFiles%\Opscope\CloudTools\<tool>.exe`; install/manage those binaries as administrator. Existing Azure/AWS trusted locations remain supported. Configure CLI authentication outside Opscope, and do not place API tokens in arguments or snapshot files.

## Examples and established Azure/AWS behavior

Install and authenticate Azure CLI/AWS CLI v2 separately. Azure Resource Graph requires its extension to be installed beforehand. Dynamic extension installation, Azure CLI telemetry/auto-upgrade, AWS pagers and interactive prompting are disabled in child processes. The official CLIs may maintain their own authentication caches; Opscope does not copy these caches or include credentials in evidence.

```sh
opscope cloud catalog
opscope cloud catalog --provider gcp
opscope gcp inventory --project <project-id>
opscope gcp metrics --project <project-id>
opscope gcp posture --projects <project-id>,<other-project-id>
opscope gcp vm --project <project-id> --resource //compute.googleapis.com/projects/<project-id>/zones/<zone>/instances/<name>
opscope oci inventory --compartment <compartment-ocid> --region <region>
opscope digitalocean health --project <project-uuid>
opscope hetzner posture --project <local-project-label>
opscope cloudflare inventory --account <32-hex-account-id>
opscope openstack health --cloud-name <reader-entry> --project <project-id> --region <region>
opscope alibaba inventory --account <account-id> --region <region> --profile <reader-profile>
opscope ibm health --account <account-id> --resource-group <resource-group-id> --region <region>
opscope scaleway inventory --project <project-uuid> --zone <zone>
```

```sh
opscope azure inventory --subscriptions <subscription-id>,<another-id>
opscope azure posture --subscription <subscription-id>
opscope azure patches --subscription <subscription-id>
opscope azure vm <full-resource-id> --subscription <subscription-id> --cloud-context
opscope azure arc --subscription <subscription-id>

opscope aws inventory --profile audit --regions eu-west-1,us-east-1
opscope aws posture --profiles audit-account-a,audit-account-b --regions eu-west-1
opscope aws instance i-0123456789abcdef0 --profile audit --region eu-west-1 --cloud-context
opscope aws patches --profile audit --region eu-west-1
opscope aws cost --profile audit --region eu-west-1

opscope cloud metadata --provider aws
opscope cloud inventory --provider azure --subscription <subscription-id>
opscope cloud posture --provider aws --profile audit --region eu-west-1 --policy examples/policies/cloud.yml
```

`cloud` detects Azure/AWS through identity-only IMDS/IMDSv2 only when explicitly invoked without `--provider` and with an operation other than `catalog`. New providers require an explicit `--provider`/direct command and configured scope. AWS never falls back to IMDSv1 or reads the IAM credentials metadata paths. Azure reads compute identity, not a Managed Identity token endpoint. Metadata requests use a fixed link-local endpoint, no proxy/redirect, strict bounds and short deadlines. `--cloud-context` enables the same optional lookup for other commands.

VM/instance reports include a separately labelled local snapshot. A local-to-cloud match is asserted only when identity metadata matches the selected normalized resource, including AWS account and region. Without a match the evidence remains explicitly unlinked. Local Arc connection metadata comes from trusted `azcmagent show --json`; SSM service installation/running state never implies cloud Online status. `environment` reports these local signals. No hybrid agent is installed or enrolled.

## Permissions and scopes

Azure Reader and Monitoring Reader are starting points for resource/monitor queries. Verify the effective role assignments, scopes and API permissions required by your tenant. Resource Graph, Defender, Update Manager, Health and Monitor may expose different coverage depending on identity and service configuration. Missing permissions or services produce explicit warnings; Opscope never enables paid capabilities.

[cloud-readonly-iam.json](cloud-readonly-iam.json) is an action-level AWS policy example covering the implemented read APIs. It deliberately contains no write, credential-value, Secrets Manager or Lambda environment actions. Some APIs require wildcard resources for account-wide inventory. Remove optional statements and constrain supported resources, regions, accounts and role trust for your deployment. The example has not been attached to a live identity or validated against your organization's IAM conditions.

Use SSO, instance roles, Managed Identity sessions or configured role profiles instead of long-lived keys. AWS cross-account traversal uses `--profiles` with already configured CLI profiles; role chaining remains in the normal AWS CLI configuration. `--accounts` is an account filter and does not create sessions. Delivery permissions are separate: this reader policy does not grant CloudWatch log writes or ticket creation.

## Drift, cost and incomplete evidence

AWS drift supports normalized unredacted exports and a documented subset of Terraform JSON state, plus existing CloudFormation drift records. Azure supports normalized exports and supported ARM/Terraform JSON identities and attributes; see [azure-drift.md](azure-drift.md). Compile Bicep to ARM JSON outside Opscope. Raw HCL/Bicep, expressions that cannot resolve to resource identities, unsupported properties and redacted/unscoped inputs are not silently treated as compliant. No deployment, plan, drift-start or IaC execution is initiated.

Terraform state and full exports can already contain sensitive data. Keep input files private. Output comparisons report changed field names rather than arbitrary expected/actual values. Default report output redacts resource identifiers; generate an explicitly protected `--full` export when a later exact baseline comparison requires identities.

Cost commands report orphan candidates and observed CPU underuse with documented sample windows. They do not delete/resize anything or promise monetary savings. Cloud API, monitoring and ingestion charges depend on the provider and account; review current service terms before use.

Reports distinguish `operationSucceeded=false` for failed required work from optional coverage warnings. CLI failure returns `2`; findings use the selected `--fail-on` threshold. Add `--require-complete` to reject any warning. An empty successful inventory remains different from an unavailable inventory.

No live tenant/account was used in the automated tests. Providers, pagination, identity validation, drift and permission failures are tested with injected CLI/HTTP transports.
