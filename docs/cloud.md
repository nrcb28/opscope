# Read-only cloud collection

Azure and AWS are optional providers using installed official CLIs and their existing authentication sessions. The core collector, offline analysis, reports, bundles and UI work without cloud accounts. The implementation uses fixed command arrays and a read-only operation allowlist; it does not launch a shell, start login, fetch secret values, install extensions, enable cloud services, run commands on machines, patch resources, or change infrastructure.

Install and authenticate Azure CLI/AWS CLI v2 separately. Azure Resource Graph requires its extension to be installed beforehand. Dynamic extension installation, Azure CLI telemetry/auto-upgrade, AWS pagers and interactive prompting are disabled in child processes. The official CLIs may maintain their own authentication caches; Opscope does not copy these caches or include credentials in evidence.

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

`cloud` detects a provider through identity-only IMDS/IMDSv2 only when explicitly invoked without `--provider`. AWS never falls back to IMDSv1 or reads the IAM credentials metadata paths. Azure reads compute identity, not a Managed Identity token endpoint. Metadata requests use a fixed link-local endpoint, no proxy/redirect, strict bounds and short deadlines. `--cloud-context` enables the same optional lookup for other commands.

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
