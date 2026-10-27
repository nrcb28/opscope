# Read-only cloud collection

Opscope has a closed registry of eleven optional infrastructure providers: `azure`, `aws`, `gcp`, `oci`, `digitalocean`, `hetzner`, `cloudflare`, `openstack`, `alibaba`, `ibm` and `scaleway`, plus the separate `kubernetes` cluster adapter. `opscope cloud catalog` reads only local descriptors; it does not discover credentials or contact a provider. `cloud catalog --provider gcp` limits the output to one adapter. Each descriptor lists actual callable operations, resource types, permission prerequisites and experimental status. The newer adapters are experimental and expose deliberately limited evidence.

The core collector, offline analysis, reports, bundles and UI work without cloud accounts. Cloud operations use fixed command arrays or fixed HTTPS API routes. They do not start login, fetch secret values, install extensions, enable cloud services, run commands on machines, patch resources or change infrastructure. A registered provider is not proof that an authenticated scope is configured or reachable.

## Provider setup and actual coverage

Configure credentials outside Opscope. Keep tokens in the existing CLI session or the named server-side environment variable; the browser has no credential, endpoint or arbitrary-scope form. `--endpoint` is a notification option and never selects a cloud provider endpoint.

| Provider | Operations | Scope and existing authentication | Evidence and minimum read access |
| --- | --- | --- | --- |
| Azure | `inventory`, `posture`, `health`, `vm`, `bundle`, `drift`, `patches`, `cost`, `arc`, `metadata` | Azure CLI; `--subscription` / `--subscriptions` | Existing Resource Graph/Compute/Monitor/Health/Defender/Update Manager data. Start with Reader/Monitoring Reader and verify each service permission. Resource Graph extension must already be installed. |
| AWS | `inventory`, `posture`, `health`, `instance`, `bundle`, `drift`, `patches`, `cost`, `metadata` | AWS CLI v2; `--profile` / `--profiles`, `--region` / `--regions` | Existing EC2, S3, CloudWatch, Health, SSM and security findings. See the [action-level example](cloud-readonly-iam.json); optional sources may require more access. |
| Google Cloud | `inventory`, `health`, `posture`, `metrics`, `services`, `scc`, `cost`, `patches`, `drift`, `vm`, `bundle` | Existing `gcloud` session; explicit `--project` / `--projects`, optional `--region`; ADC for Monitoring, SCC, billing and OS Config reads | Selected Asset Search resources, Compute state/firewall, optional service configuration, Monitoring CPU, existing SCC findings, observed billing-export rows and existing patch-job metadata. Drift compares a compatible private inventory baseline. Permissions depend on the operation; details below. |
| Oracle Cloud | `inventory`, `health`, `posture`, `metrics` | Existing OCI CLI profile; `--compartment <ocid> --region <region>`, optional `--profile` | Selected Compute state/network configuration and `oci_computeagent` CPU utilization. Metrics need Monitoring read access in that explicit compartment. |
| DigitalOcean | `inventory`, `health`, `posture`, `metrics` | `DIGITALOCEAN_ACCESS_TOKEN`; explicit `--project <uuid>` | Project resources, associated droplets/volumes, selected firewalls and native CPU counter series. Use a read-only token with project/resource, firewall and Monitoring read access for the requested operation. |
| Hetzner Cloud | `inventory`, `health`, `posture`, `metrics` | `HCLOUD_TOKEN`; explicit `--project <local-label>` matching the token's project | Token-scoped Cloud servers, selected network configuration and provider CPU history. Use a read-only project token. The label is not independent proof of the token's project identity. |
| Cloudflare | `inventory`, `health`, `posture`, `metrics` | `CLOUDFLARE_API_TOKEN`; `--account <32-hex-id>` and explicit `--zones <ids>` for metrics | Zone metadata/state/paused configuration; optional GraphQL request, byte and cache counts for account-verified zones. Use Zone:Read and Analytics:Read with resource restrictions. No WAF assessment or availability probe is implied. |
| OpenStack | `inventory`, `health`, `posture`, `metrics` | Existing OpenStack CLI `clouds.yaml`; `--cloud-name <entry> --project <uuid> --region <name>` | Selected project servers and security groups; optional Gnocchi resource/measure reads. The existing CLI configuration supplies endpoints/CA; metrics require the Gnocchi plugin and read access to owned resources. |
| Alibaba Cloud | `inventory`, `health`, `posture`, `metrics` | Existing Alibaba CLI profile; `--account <id> --region <name>`, optional `--profile` and `--metric-resources <ids>` | Selected ECS instances, disks/VPCs and CloudMonitor CPU utilization. Posture checks explicit disk-encryption metadata. Grant the used Describe/identity and CloudMonitor read calls; no guest/application health is inferred. |
| IBM Cloud | `inventory`, `health`, `metrics` | Externally refreshed `IBM_CLOUD_IAM_TOKEN`; explicit `--account <id> --resource-group <id> --region <name>`; `--monitoring-instance <guid>` for metrics | Resource Controller metadata/state. Optional Monitoring Prometheus `up` observations require a Sysdig Monitor instance verified against that account, group and region. This adapter does not query VPC infrastructure. |
| Scaleway | `inventory`, `health`, `metrics` | `SCW_SECRET_KEY`; explicit `--project <uuid> --zone <name>`; `--cockpit-source <uuid>` and `SCW_COCKPIT_TOKEN` for metrics | Selected Instance servers/volumes and optional Cockpit Prometheus `up` observations. Data-source metadata, type, region, URL and project must match before metric reads. |
| Kubernetes | `inventory`, `health`, `metrics` | Existing approved kubeconfig context; explicit `--context <name>` and `--namespaces <names>` | Namespace-scoped workload/service metadata and optional Metrics Server pod CPU/memory. Node metadata requires `--kubernetes-nodes`. Kubernetes is a cluster source, not an additional infrastructure provider. |

The catalog is authoritative if this table and an older command example differ. Experimental adapters do not advertise unsupported billing, patch compliance or metric operations. `RUNNING`, `active`, zone state, a configuration rule or an empty response does not establish application availability or complete security coverage. Coverage includes source, freshness, warnings and an explicit state; missing data is not converted to a zero metric.

Google Cloud inventory includes selected Compute, GKE, Cloud SQL, Cloud Run and Storage **asset metadata**. The separate `services` operation adds whitelisted configuration/state: `--gcp-services gke,sql,storage` is the default, and selecting `run` requires an explicit `--region`. It reports GKE version/current-node counts, SQL HA/backup-enabled configuration, Cloud Run Ready/revision-observed metadata and Storage access-prevention configuration where available. Service reads use exact gcloud projections: Cloud Run annotations, ingress configuration and pod specifications are excluded. They do not read bucket objects or database contents, invoke service URLs or infer application availability. A backup-enabled setting does not prove restore readiness. Required reads include project identity plus the selected `container.clusters.list`, `cloudsql.instances.list`, `run.services.list` or `storage.buckets.list` permission. OS Config job evidence and the separate inventory-baseline comparison are described below.

Cloud Monitoring, SCC, billing and OS Config reads use separately configured Application Default Credentials (ADC). Google Cloud uses the existing configured `gcloud` session and ADC; `--profile` is not a Google Cloud identity selector and is rejected before provider reads. Configure the intended CLI identity outside Opscope. The existing `gcloud` CLI session does not itself configure ADC. Configure ADC outside Opscope using your organization's workload identity or supported ADC workflow; the app never starts login. Tokens stay in the backend authentication flow and are never printed, persisted by Opscope or exposed to the browser. Monitoring requires `monitoring.timeSeries.list`/Monitoring Viewer and preserves a fixed fifteen-minute window with sixty-second mean alignment. Missing ADC or permission remains explicit partial/not-configured coverage; independent CLI inventory/state reads stay usable. A `gcp vm`/bundle local snapshot remains separate unless an independently supported identity check establishes the same resource; Google Cloud metadata linking is not implemented.

`gcp scc` reads existing global Security Command Center v1 findings for the selected project. Resource Manager first binds the configured project ID to its project number; returned finding resources must match that project. Required reads include `resourcemanager.projects.get` and `securitycenter.findings.list`, subject to SCC edition/configuration and IAM. An empty list or HTTP 403 is never a secure-project verdict.

`gcp cost` requires an existing export specified by `--billing-project <id> --billing-dataset <id> --billing-table <id>`, in addition to the authorized billed `--project`/`--projects`. It issues only table metadata and `tabledata.list` GETs, requiring `bigquery.tables.get`/`bigquery.tables.getData`; it creates no query, job, export or dataset. The table must be a supported existing billing-export table. Up to 1,000 observed rows are read across at most ten pages; client-side project filtering and currency-separated subtotals remain explicitly incomplete (`isComplete=false`). Credits are preserved, currencies are never added together, and missing rows mean unknown cost. These observations are neither a complete invoice nor a forecast. SCC/billing reads have thirty-second operation budgets, 4 MiB per response and 8 MiB aggregate response limits.

`gcp patches` reads metadata and aggregate results of existing OS Config patch jobs in the explicitly selected projects. Resource Manager verifies each project ID/number before the OS Config read. The reader omits free-text descriptions, script settings and arbitrary instance filters. It never starts a patch job, installs the OS Config agent or enables VM Manager. A successful historical job is not current compliance: `complianceState` remains `unknown`, and missing, stale or denied evidence cannot become a patched/healthy verdict. Required permissions are `resourcemanager.projects.get` and `osconfig.patchJobs.list`, using existing ADC with the cloud-platform scope. The operation accepts one to twenty projects and reads at most ten pages per project, 1,000 jobs and sixty HTTP requests overall, with a thirty-second operation deadline, 4 MiB per response and 8 MiB aggregate. Job create/update timestamps remain provider observations; an update older than twenty-four hours is marked stale, while a missing timestamp remains unknown. Missing aggregate counters remain null rather than zero.

`gcp drift` requires `--baseline <path>` pointing to a private, unredacted JSON export of a compatible `gcp inventory` run. It compares resource presence and only shared known `region`/`state` values, with the same explicit projects, region/resource filters and asset-type provenance. GCP inventory scope records `profile: null`; a non-null profile in a baseline is rejected because it does not prove a selected Google Cloud identity. If either inventory has partial coverage, the reader suppresses added/missing assessments while retaining comparable fields on resources observed in both. Redacted or invalid identities, malformed input and mismatched scopes prevent comparison; missing or redacted attributes remain unknown. Regenerate older exports that lack the inventory-scope metadata. The input limit is 16 MiB and 10,000 resources, with bounded JSON depth and complexity. Incomplete enumeration cannot establish an absent resource, and missing attributes cannot establish complete conformance. This is a comparison of two observations, not a Terraform plan, deployment or proof of continuous compliance; raw HCL, Terraform state and arbitrary JSON properties are not supported for this GCP workflow.

Cloud metric histories are provider observations, separate from the five-second host sampler. Hetzner CPU history requests a sixty-second step over the preceding hour, caps reads at ten enumerated servers and retains the provider's returned period, unit and timestamps. DigitalOcean retains cumulative CPU seconds per CPU/mode for at most ten project-allowlisted droplets; these are not instantaneous CPU percentages. A response without observations remains `no_data`, not a zero series. Histories are bounded to 1,000 series/10,000 points per collection; resource/read limits can produce explicit partial coverage.

The supplemental readers use a fixed last-hour window. OCI returns CPU utilization percentages with sixty-second means in the selected compartment; it does not traverse subcompartments. OpenStack Gnocchi measures preserve native units: cumulative CPU nanoseconds remain nanoseconds and memory measures retain their declared byte/MB/MiB units. Cloudflare returns five-minute request/byte/cache counts for at most twenty explicitly selected zones after checking zone ownership. Alibaba requests sixty-second CloudMonitor CPU utilization for at most ten authorized ECS instances and preserves the actual period returned by the provider. IBM Monitoring and Scaleway Cockpit expose the `up` scrape-target gauge, a ratio of zero or one; it is not CPU usage or proof of application availability. These readers do not change cloud resources, refresh measures or retry quota failures automatically. Missing agents, telemetry services or permissions remain explicit. The UI keeps each unit/source separate from host CPU/RAM.

## Kubernetes cluster scopes

An existing administrator-approved kubeconfig context and one to twenty explicit namespaces are mandatory. `--namespace <name>` is the single-namespace alias. No browser request can supply kubeconfig, a cluster endpoint, bearer token or an all-namespaces wildcard. `serve --cloud kubernetes --kubernetes-contexts <context> --namespaces <names>` binds those choices before printing the session URL. Context and namespace identifiers remain redacted in shared evidence.

The fixed kubectl metadata projections cover pods, deployments, statefulsets, daemonsets, services and safe event type/reason/time/count fields. They omit pod environment/commands, raw specs, event messages, Secrets, ConfigMaps and logs. The adapter never runs exec, port-forward or mutation commands. Nodes are cluster-scoped and are queried only with `--kubernetes-nodes`; remove that opt-in when namespace-only RBAC is required. Context authentication uses the existing approved CLI configuration.

Inventory/health verifies each selected namespace using `get namespaces <name>`; grant cluster-scoped `get` constrained with `resourceNames`, without granting namespace enumeration. Workload/service/event reads can use `get`/`list` in per-namespace Roles. Metrics only needs the selected namespaced `metrics.k8s.io` pod reads and verifies returned namespace identities. Node reads need separate cluster-scoped access. The adapter installs neither RBAC nor Metrics Server. Projected output is limited to 1 MiB and ten seconds per kubectl invocation, 1,000 resource rows and sixty seconds per collection; kubectl manages its own 100-item server chunks within those budgets. Missing permissions or Metrics Server cannot become a zero measurement.

Pod metrics are single recent observations in CPU millicores and memory bytes, with the provider timestamp/window. They are not percentages or a retained cloud history. The UI displays their values and sample tables even when there are too few points to draw a line.

Node-to-infrastructure matching is an additional opt-in: `--kubernetes-nodes --infrastructure-provider gcp` with an explicit project scope, or `--infrastructure-provider azure` with an explicit subscription scope. Opscope reads the selected provider inventory in the backend and compares canonical node `providerID` references against normalized resources in that scope. Matching is exact against successful inventory and cluster observations no older than five minutes; timestamps more than two minutes in the future are rejected. Google Cloud also requires explicit complete coverage; Azure requires successful inventory without incomplete/truncation warnings and honors explicit coverage when present. Duplicate node references or ambiguous infrastructure IDs do not establish a verified link. Names alone do not establish a link. Azure VM scale-set identities are outside the supported VM inventory and remain unverified. A verified match establishes only the observed node reference, not control-plane identity, cluster ownership, host identity or application availability. AWS node references lack an independent account binding in this workflow and remain unverified. The result distinguishes all observed node references matched, some matched, and no verified match. It reports only observed links, with at most 1,000 nodes and 10,000 infrastructure resources across twenty reports. No browser request can supply provider IDs, inventory contents or new scopes.

## Configure the local Cloud workspace

The server binds providers, operations and scopes before printing the session URL. For example:

```sh
opscope serve --cloud azure,aws,gcp --subscriptions <subscription-id> --profiles audit --gcp-projects <project-id> --regions eu-west-1
opscope serve --cloud digitalocean --digitalocean-projects <project-uuid>
opscope serve --cloud openstack --cloud-name production-reader --openstack-projects <project-id> --region RegionOne
opscope serve --cloud kubernetes --kubernetes-contexts <reader-context> --namespaces monitoring,application
opscope serve --cloud gcp --gcp-projects <project-id> --baseline baseline.json
opscope serve --cloud kubernetes --kubernetes-contexts <reader-context> --namespaces application --kubernetes-nodes --infrastructure-provider gcp --project <project-id>
```

A session accepts the twelve registered source adapters and at most twenty total scope choices. New adapters require an explicit scope. The browser receives anonymous labels such as `gcp-scope-1`, never a free-form scope selector. Provider-specific allowlists prevent a Google Cloud project ID being reused as a DigitalOcean project: `--gcp-projects`, `--digitalocean-projects`, `--hetzner-projects`, `--openstack-projects`, `--scaleway-projects`, `--oci-compartments`, `--cloudflare-accounts`, `--alibaba-accounts`, `--ibm-accounts` and `--kubernetes-contexts`. Generic `--projects`, `--compartments`, `--accounts` or `--contexts` apply only where that scope type is intentional. Region/profile/namespace/token context remains fixed for the session; use separate sessions for sources needing different values of a shared option.

Only advertised read actions with server-bound configuration are exposed in the workspace. Google Cloud drift is available only when an inventory baseline path is configured at server startup with `--baseline`; the browser cannot select a local path or submit a baseline. VM/instance, bundle, Azure/AWS drift, Arc and identity metadata commands remain explicit CLI workflows. Changing a provider in the UI cannot discover new accounts, install credentials or expand the server allowlist.

CLI executables must come from trusted installation locations, not the working directory or an arbitrary PATH entry. On Unix use the supported root-owned system/vendor locations (for example `/usr/bin`, `/usr/local/bin`, or the documented vendor `/opt` directory). On Windows the additional provider CLI executables use `%ProgramFiles%\Opscope\CloudTools\<tool>.exe`; install/manage those binaries as administrator. Existing Azure/AWS trusted locations remain supported. Configure CLI authentication outside Opscope, and do not place API tokens in arguments or snapshot files.

## Examples and established Azure/AWS behavior

Install and authenticate Azure CLI/AWS CLI v2 separately. Azure Resource Graph requires its extension to be installed beforehand. Dynamic extension installation, Azure CLI telemetry/auto-upgrade, AWS pagers and interactive prompting are disabled in child processes. The official CLIs may maintain their own authentication caches; Opscope does not copy these caches or include credentials in evidence.

```sh
opscope cloud catalog
opscope cloud catalog --provider gcp
opscope gcp inventory --project <project-id>
opscope gcp metrics --project <project-id>
opscope gcp posture --projects <project-id>,<other-project-id>
opscope gcp services --project <project-id> --gcp-services gke,sql,storage
opscope gcp services --project <project-id> --gcp-services run --region <region>
opscope gcp scc --project <project-id>
opscope gcp patches --project <project-id>
opscope gcp inventory --project <project-id> --full --format json --out baseline.json
opscope gcp drift --project <project-id> --baseline baseline.json
opscope gcp cost --project <billed-project-id> --billing-project <export-project-id> --billing-dataset <dataset-id> --billing-table <table-id>
opscope gcp vm --project <project-id> --resource //compute.googleapis.com/projects/<project-id>/zones/<zone>/instances/<name>
opscope oci inventory --compartment <compartment-ocid> --region <region>
opscope digitalocean health --project <project-uuid>
opscope hetzner posture --project <local-project-label>
opscope cloudflare inventory --account <32-hex-account-id>
opscope openstack health --cloud-name <reader-entry> --project <project-id> --region <region>
opscope alibaba inventory --account <account-id> --region <region> --profile <reader-profile>
opscope ibm health --account <account-id> --resource-group <resource-group-id> --region <region>
opscope scaleway inventory --project <project-uuid> --zone <zone>
opscope oci metrics --compartment <compartment-ocid> --region <region>
opscope cloudflare metrics --account <32-hex-account-id> --zones <32-hex-zone-id>
opscope openstack metrics --cloud-name <reader-entry> --project <project-uuid> --region <region>
opscope alibaba metrics --account <account-id> --region <region> --metric-resources <instance-id>
opscope ibm metrics --account <account-id> --resource-group <resource-group-id> --region <region> --monitoring-instance <monitor-guid>
opscope scaleway metrics --project <project-uuid> --zone <zone> --cockpit-source <source-uuid>
opscope kubernetes inventory --context <reader-context> --namespaces monitoring,application
opscope kubernetes metrics --context <reader-context> --namespace application
opscope kubernetes inventory --context <reader-context> --namespaces application --kubernetes-nodes --infrastructure-provider gcp --project <project-id>
opscope kubernetes inventory --context <reader-context> --namespaces application --kubernetes-nodes --infrastructure-provider azure --subscription <subscription-id>
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

Google Cloud drift accepts only the compatible unredacted normalized inventory export described above; its exact scope is required, and added/missing assessments require complete coverage in both observations. AWS drift supports normalized unredacted exports and a documented subset of Terraform JSON state, plus existing CloudFormation drift records. Azure supports normalized exports and supported ARM/Terraform JSON identities and attributes; see [azure-drift.md](azure-drift.md). Compile Bicep to ARM JSON outside Opscope. Raw HCL/Bicep, expressions that cannot resolve to resource identities, unsupported properties and redacted/unscoped inputs are not silently treated as compliant. No deployment, plan, drift-start or IaC execution is initiated.

Terraform state and full exports can already contain sensitive data. Keep input files private. Output comparisons report changed field names rather than arbitrary expected/actual values. Default report output redacts resource identifiers; generate an explicitly protected `--full` export when a later exact baseline comparison requires identities.

Azure/AWS cost commands report orphan candidates and observed CPU underuse with documented sample windows. Google Cloud cost reads the explicitly configured export rows described above. None deletes/resizes resources or promises monetary savings. Cloud API, monitoring and ingestion charges depend on provider/account terms.

Reports distinguish `operationSucceeded=false` for failed required work from optional coverage warnings. CLI failure returns `2`; findings use the selected `--fail-on` threshold. Add `--require-complete` to reject any warning. An empty successful inventory remains different from an unavailable inventory.

No live tenant/account was used in the automated tests. Providers, pagination, identity validation, drift and permission failures are tested with injected CLI/HTTP transports.
