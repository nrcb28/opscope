# Azure drift baselines

Azure drift reads bounded local JSON and compares supported resource identities plus explicitly supplied location, VM size, OS type and encryption fields. It never deploys, validates a deployment, evaluates ARM expressions, executes Terraform or compiles Bicep.

Keep an inventory baseline with concrete identities in a private location:

```sh
opscope azure inventory --subscription YOUR_SUBSCRIPTION_GUID --full --out baseline.json
opscope azure drift --subscription YOUR_SUBSCRIPTION_GUID --baseline baseline.json
```

The normal redacted report is suitable for sharing; a drift baseline requires the original resource identities, so `--full` is explicit. Exported inventory now records its subscription, region and resource filters in a versioned `scope` object. Use the same scope when comparing.

Supported inputs are exported Azure inventory with concrete ARM resource IDs, Terraform state/show JSON with actual ARM IDs, and ARM declarations whose concrete type/name resolves to exactly one live resource in the selected scope. Unresolved or ambiguous declarations and unsupported resource types produce coverage warnings. Additional live resources are not assumed to be drift.

`operationSucceeded` is false, with CLI exit code 2, when the baseline is missing, unreadable, malformed, unsupported Bicep source, fully redacted, outside the selected subscription scope, or yields no usable supported identities. A successful comparison can still find drift and return exit code 1 according to `--fail-on`. Optional coverage warnings leave operation success true; `--require-complete` makes the CLI return 2 when warnings remain.

An empty baseline succeeds only when it is a successful unredacted Azure inventory export with matching explicit subscription/region/resource scope and the live inventory is also empty. Arbitrary empty arrays, old exports without scope, failed inventory collections and redacted scopes do not prove absence. The comparison remains limited to the six supported inventory resource types.

When some baseline resources can be compared and others are unsupported, the usable comparisons are retained and `operationSucceeded` remains true with coverage warnings. No unsupported or unavailable evidence is treated as compliance.
