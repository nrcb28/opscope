# opscope

[Español](#español) · [English](#english)

## Español

`opscope` diagnostica Linux, Windows y macOS desde la terminal o una interfaz web local autenticada. Recoge snapshots, muestra problemas de salud y seguridad y genera evidencia para soporte sin instalar un agente de monitorización. Los binarios autocontenidos incluyen el runtime; las compilaciones dependientes del framework necesitan el runtime ASP.NET Core de .NET 8.

### Requisitos y primer arranque

Para compilar, instala el SDK **8.0.426** o un parche posterior de la misma banda, según `global.json`. Node.js 22 o posterior solo se usa en las pruebas de navegador; la interfaz incorpora sus recursos y no usa CDN.

```bash
dotnet build src/Opscope/Opscope.csproj -c Release
dotnet run --project src/Opscope/Opscope.csproj -- serve
```

Abre la URL que imprime la terminal. Su token es propio de esa sesión: el servidor escucha en `127.0.0.1` y no publica la interfaz en la red. Selecciona **ES** para cambiar de idioma. Las utilidades nativas y los permisos disponibles determinan la cobertura; una fuente ausente se comunica como no evaluada.

La gráfica ligera recoge CPU y memoria del host cada cinco segundos en Linux, Windows y macOS, sin enumerar procesos en cada muestra. En macOS la memoria se presenta como una estimación basada en páginas libres e inactivas; no es un indicador de presión de memoria ni una reproducción de Activity Monitor. La primera lectura CPU y los contadores no disponibles permanecen sin valor.

### Descargar una compilación instalable

Las ejecuciones aprobadas de [CI en GitHub](https://github.com/nrcb28/opscope/actions/workflows/ci.yml) generan el artefacto `package-assets`, conservado durante catorce días. Descárgalo desde **Artifacts** de la ejecución y extrae el archivo de tu sistema y arquitectura. La versión candidata combina la versión del proyecto con `-ci.<número de ejecución>`.

Los archivos autocontenidos incluyen .NET: ejecuta `./opscope serve` en Linux/macOS o `.\opscope.exe serve` en PowerShell. El paquete `.nupkg` es una alternativa para `dotnet tool` y requiere el runtime ASP.NET Core de .NET 8. [Instalación, comprobación de integridad y límites de distribución](docs/delivery.md#candidate-packages-from-ci).

### Usos de la interfaz

| Vista | Uso |
| --- | --- |
| Resumen, Hallazgos, Procesos/Puertos y Servicios | Inspeccionar el equipo actual y buscar evidencia con tablas paginadas. |
| Laboratorio de evidencia | Cargar un snapshot JSON, inspeccionarlo, ejecutar triaje, comparar IoC CSV/STIX y crear una cronología con baseline opcional. |
| Comparación de cambios y de flota | Comparar una baseline con el equipo actual o varios snapshots entre sí. |
| Historial y cronología | Consultar observaciones redactadas retenidas en SQLite. |
| Cloud | Consultar los proveedores y ámbitos configurados antes de iniciar la sesión. |
| Conexiones | Revisar la preparación del host, abrir guías oficiales y probar una lectura ya configurada. |
| Política | Validar y evaluar YAML en memoria; descargar el borrador sin aplicar cambios al host. |
| Informes y bundle | Descargar evidencia redactada y un ZIP cuyo digest verifica el navegador. |

El laboratorio mantiene su evidencia separada del equipo en vivo y del historial. Admite **2 MiB por petición** y **128 KiB de indicadores**, exige UTF-8 y limita cada carga a diez segundos. Compara observables guardados: no consulta DNS o feeds remotos ni escanea archivos del equipo actual. Un resultado sin coincidencias no demuestra ausencia de compromiso. El botón de limpiar descarta el estado del laboratorio en memoria.

La comparación de cambios solo se habilita al terminar de validar la baseline. Mientras se carga o compara una selección, el botón evita clics prematuros o duplicados; una respuesta antigua no puede sustituir una selección posterior.

### Comandos frecuentes

```bash
dotnet run --project src/Opscope -- snapshot --redact --json --out snapshot.json
dotnet run --project src/Opscope -- doctor --fail-on critical
dotnet run --project src/Opscope -- report snapshot.json --format html --out informe.html --quiet
dotnet run --project src/Opscope -- triage --input snapshot.json --scenario high-cpu
dotnet run --project src/Opscope -- ioc examples/iocs/sample.csv --input snapshot.json
dotnet run --project src/Opscope -- timeline --input snapshot.json --format csv
dotnet run --project src/Opscope -- policy validate examples/policies/opscope.yml
dotnet run --project src/Opscope -- bundle --out evidencia.zip
```

Con el binario o la herramienta instalada, sustituye `dotnet run --project src/Opscope --` por `opscope`. Los ejemplos pueden devolver `1` cuando encuentran un problema; eso no significa que la ejecución haya fallado. Códigos: **0** sin hallazgos al umbral elegido, **1** hallazgo o verificación fallida y **2** error de entrada/ejecución. `--require-complete` también rechaza avisos de cobertura. Los modos en vivo rechazan `--input`; los análisis guardados rechazan opciones que introducirían evidencia nativa de otro equipo.

Los informes admiten JSON, SARIF, JUnit, HTML, PDF, CSV, JSONL y CEF; ASFF exige cuenta y región reales. Bundles e historial siempre están redactados. El `snapshot` detallado predeterminado puede contener información sensible: usa `--redact` antes de compartirlo. Las firmas RSA-PSS necesitan una clave pública confiable obtenida por otro canal; un hash por sí solo no autentica al remitente.

### Cloud, seguridad y desarrollo

El catálogo incluye Azure, AWS, Google Cloud, OCI, DigitalOcean, Hetzner, Cloudflare, OpenStack, Alibaba, IBM y Scaleway, más Kubernetes como adaptador de clúster separado. `opscope cloud catalog` muestra operaciones y permisos sin consultar credenciales. Las lecturas avanzadas incluyen SCC, configuración de servicios GCP con metadatos acotados de node pools GKE, filas de una exportación de facturación existente, jobs OS Config ya registrados y métricas opcionales con sus unidades reales. GCP puede comparar un inventario con una baseline privada compatible. DigitalOcean verifica el proyecto antes del inventario de droplets, volúmenes y balanceadores, conserva las VPC referenciadas por esos recursos y observa membresía de firewalls directa o por tags sin exportar los tags. Cloudflare añade comprobaciones seleccionadas de TLS y metadatos DNS/WAF/rutas; Alibaba conserva el cifrado observado de discos y añade configuración de security groups; IBM ofrece metadatos regionales VPC/subnets/security groups con cuenta y resource group verificados; Scaleway ofrece inventario regional VPC/redes privadas. Cada lectura conserva su ámbito y cobertura; la configuración no prueba salud ni conectividad. Kubernetes exige un contexto y namespaces explícitos; el enlace opcional a infraestructura verifica referencias de nodos, no la identidad del clúster. Las fuentes necesitan CLI autenticadas o credenciales de lectura y ámbitos configurados; los adaptadores nuevos son experimentales con cobertura limitada. La recolección local funciona sin cuentas cloud, y no activa servicios ni inicia sesión. Las notificaciones requieren `--confirm-send`; no hay envío desde la web.

El menú **Conexiones** muestra los ámbitos configurados, los requisitos de credenciales/herramientas y el resultado de la última lectura de cada proveedor. Incluye enlaces oficiales de alta y guías de autenticación para ejecutar en el host de Opscope. La presencia de un token o de una CLI no prueba acceso a la cuenta; abrir la guía no inicia sesión ni crea cuentas. Para usar la interfaz desde un servidor, consulta [el acceso remoto mediante proxy HTTPS autenticado o túnel SSH](docs/remote-hosting.md).

Las consultas cloud tienen su propio límite de concurrencia y no bloquean la recolección local. La interfaz identifica las respuestas reutilizadas de caché y conserva su fecha original. Una cuota del proveedor impone una espera local al ámbito afectado; no pausa la recolección del host ni reintenta la consulta automáticamente. [Límites, caché y reintentos](docs/cloud.md#ui-scheduling-cache-and-retries).

La recolección no detiene procesos, cambia servicios, modifica el firewall ni eleva privilegios. La redacción es acotada: si no puede completar su contexto, omite texto y lo indica conservando cifras y severidades. Consulta la [política de seguridad](SECURITY.md), los [permisos cloud](docs/cloud.md), los [contratos de la API](src/Opscope.Api/README.md) y los [límites de las propuestas](docs/proposals.md) y la [matriz de la auditoría UI/multicloud v4](docs/engineering-review-v4.md).

```bash
python3 tests/cli_smoke.py
dotnet run --project tests/Opscope.ReportingTests -c Release
dotnet build tests/Opscope.ApiTests/Opscope.ApiTests.csproj
cd tests/Opscope.ApiTests
npm ci
npx playwright install --with-deps chromium
npm test
```

Compila primero la CLI en Release para las pruebas Python. En Windows puedes usar `python` o `py` si `python3` no está disponible. CI ejecuta todos los proyectos de regresión .NET, CLI y pruebas de humo en Linux/Windows/macOS, y el navegador en Linux/Windows. Los comentarios explican las decisiones clave en **EN/ES**; los identificadores, comandos y esquemas públicos mantienen sus nombres para conservar compatibilidad. La preparación de releases genera artefactos y borradores; no publica automáticamente paquetes ni convierte un borrador en release pública.

## English

`opscope` is a cross-platform systems operations CLI for Linux, Windows and macOS, with an authenticated local web interface. It is designed for the first ten minutes of an incident: capture a reliable host snapshot, spot degraded signals, inspect processes and listening sockets, and produce a shareable support bundle without installing a monitoring agent. Self-contained builds include the runtime; framework-dependent builds require the .NET 8 ASP.NET Core runtime.

### What it does

- Host inventory: OS, kernel/runtime, architecture, boot time, uptime and elevation state.
- Health signals: memory pressure, disk pressure, network reachability and failed services.
- Process inventory with CPU time, memory and command line when the OS permits access.
- Listening socket discovery using native `ss`/`netstat` tooling when available.
- Service discovery, including failed units, using `systemctl` on Linux and `sc.exe` on Windows.
- Security posture: host firewall state and wildcard-bound listeners, with actionable exposure findings.
- Firewall reports distinguish enabled state and rules from effective protection, which remains unverified when the collector cannot establish complete coverage.
- Snapshot drift detection across metrics, processes, services, disks, listeners, firewall/tool trust and coverage.
- Stable snapshot JSON plus SARIF, JUnit, HTML/PDF, CSV, JSONL, CEF and real-context ASFF exports.
- Strict YAML policies, declarative plugins and bounded scenario packs.
- Optional catalog-driven collection across eleven infrastructure providers plus a separate namespace-allowlisted Kubernetes adapter; advanced Google Cloud SCC/service metadata/billing-export reads and optional provider metrics preserve explicit scope and coverage.
- IoC matching, observed timelines, fleet outliers and contextual triage.
- Authenticated loopback UI, redacted SQLite history, Prometheus, SSE and narrow MCP tools.
- Custody manifests, SHA-256, optional RSA-PSS signatures and AES-GCM/RSA-OAEP encryption.
- Redacted ZIP support bundles containing a snapshot, findings, process list, network data and collection metadata.
- Watch mode for a compact live dashboard.

Collection is read-only: it does not stop processes, change services, modify firewall rules or send telemetry. Explicit cloud queries and confirmed notification delivery are optional separate operations.

### Requirements

- .NET 8 ASP.NET Core runtime for the framework-dependent build (the CLI includes its local API), or a self-contained publish. Source builds require the .NET 8 SDK.
- Source builds use SDK 8.0.426 or a later servicing patch in the same feature band, as pinned in `global.json`, so installed newer SDKs do not change compiler/analyzer behavior.
- Browser tests require Node.js 22 or later; the embedded production UI does not need Node.js or CDN resources.
- Linux: `ss` and `systemctl` provide core coverage; `lsof`, `journalctl`, `resolvectl`, `ip` and supported firewall tools are optional enrichments. `lsof` is used as a read-only listener fallback.
- Windows: `netstat`, `netsh` and `sc.exe` provide core coverage; `tasklist.exe` and `wevtutil.exe` are optional diagnostics enrichments.

The package workflow targets `linux-x64`, `linux-arm64`, `win-x64`, `win-arm64`, `osx-x64` and `osx-arm64`. A successful [CI run](https://github.com/nrcb28/opscope/actions/workflows/ci.yml) provides a `package-assets` artifact for fourteen days, with a run-specific `-ci.<run number>` version. Extract the archive matching your operating system and architecture, then run `./opscope serve` or `.\opscope.exe serve`. Self-contained archives include .NET; the `.nupkg` tool requires the .NET 8 ASP.NET Core runtime. [Download, verification and installation details](docs/delivery.md#candidate-packages-from-ci).

### Build and run

```bash
dotnet build src/Opscope/Opscope.csproj -c Release
dotnet run --project src/Opscope/Opscope.csproj -- snapshot
dotnet run --project src/Opscope/Opscope.csproj -- snapshot --json --out snapshot.json
dotnet run --project src/Opscope/Opscope.csproj -- doctor
dotnet run --project src/Opscope/Opscope.csproj -- bundle --out ./incident-bundle.zip
dotnet run --project src/Opscope/Opscope.csproj -- diff ./baseline.json
dotnet run --project src/Opscope/Opscope.csproj -- tools --json
dotnet run --project src/Opscope/Opscope.csproj -- watch --interval 5
```

For a portable binary:

```bash
dotnet publish src/Opscope/Opscope.csproj -c Release -r linux-x64 --self-contained true -p:PublishSingleFile=true -o artifacts/linux-x64
dotnet publish src/Opscope/Opscope.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o artifacts/win-x64
```

### Exit codes

- `0`: requested work completed without a finding at the selected threshold.
- `1`: a finding meets `--fail-on`, or archive verification failed.
- `2`: invalid input or required work could not complete. `--require-complete` also rejects coverage warnings.

### Commands

| Command | Purpose |
| --- | --- |
| `snapshot` | Collect and print a full host snapshot. |
| `doctor` | Collect a snapshot and print only actionable findings. |
| `bundle` | Create a ZIP with redacted JSON evidence for incident handoff. |
| `watch` | Refresh a compact health dashboard until Ctrl+C. |
| `diff <snapshot.json>` | Compare a saved baseline with a fresh collection from the current host. |
| `tools` | Inventory required/enrichment utilities, trusted paths, permissions and versions. |
| `version` | Print build/runtime information. |

Common options: `--json`, `--redact`, `--out <path>`, `--no-processes`, `--no-network`, `--no-services`, `--top <n>`, `--interval <seconds>`, `--help`.

Use `snapshot --redact --json --out safe-snapshot.json` when the output may leave the host. This omits process command lines and redacts host, user, network-address and filesystem-root identifiers. The default snapshot remains detailed for local troubleshooting.

`diff` returns exit code `1` when it detects a significant metric change, a host mismatch, or an added/removed/changed process, service or listener. Save a baseline with `snapshot --json --out baseline.json`, then run `diff baseline.json` during a maintenance window or incident investigation.

`tools` checks the native utilities used for enrichment (`ss`, `systemctl`, `lsof`, `journalctl`, `resolvectl`, `netstat`, `netsh`, `sc.exe`, `tasklist.exe`, `wevtutil.exe`, firewall utilities and `ip`). It reports missing coverage and fails if an available utility is outside the trusted system locations, writable by a non-owner, non-executable or otherwise not securely inspected. Every optional tool uses the same fixed-path, owner, permission, ACL and reparse-point validation before execution.

The regression suite covers localized UFW parsing, nftables inbound-scope verification, unsafe executable blocking, private output permissions, typed redaction of addresses/ports/paths/identities, preservation of incomplete collection state, and diff detection before redaction.

### Security and privacy

Collection is local and read-only. External commands are launched without a shell, with fixed executable resolution and bounded output. Support bundles omit process command lines and redact host, user, network-address and filesystem-root identifiers. Treat snapshots and bundles as operational evidence: service names, listener counts and package/runtime versions can still be sensitive. See [SECURITY.md](SECURITY.md) for the reporting policy.

### Repository layout

```text
src/Opscope/       CLI and command dispatch
src/Opscope.Core/  Collection, models, drift, redaction and bounded input
src/Opscope.Cloud/ Optional read-only cloud registry, CLI and bounded HTTPS adapters
src/Opscope.Reporting/ Policies, packs, exports and protected bundles
src/Opscope.Evidence/ Optional evidence, IoCs, timeline and fleet
src/Opscope.Api/   Embedded local UI, history, metrics and MCP
src/Opscope.Integrations/ Explicit opt-in delivery
tests/             Cross-platform smoke scripts
.github/workflows/ Build matrix for Linux, Windows and macOS
tests/Opscope.Tests/ Deterministic parser and security regression tests
.gitattributes       Cross-platform line-ending policy
SECURITY.md          Vulnerability reporting and data-handling notes
```



### Implemented proposal commands

```sh
opscope policy validate examples/policies/opscope.yml
opscope snapshot --policy examples/policies/opscope.yml --json --out policy-baseline.json
opscope doctor --policy examples/policies/opscope.yml --format sarif --out findings.sarif
opscope plugins check examples/policies/plugin-exposure.yml
opscope pack validate examples/packs/ssh-comprometido.yml
opscope snapshot --pack examples/packs/disk-full.yml --redact --json --out scenario.json
opscope report baseline.json --format html --out handoff.html --quiet
opscope report baseline.json --format pdf --out handoff.pdf --quiet
opscope triage --scenario disk-full
opscope ioc examples/iocs/sample.csv
opscope timeline baseline.json --evidence logs --format csv --out timeline.csv
opscope fleet host-a.json host-b.json --format json
opscope tui --page services --interval 5
opscope environment
```

An explicit `--policy` or a local `opscope.yml` applies configurable CPU/memory/disk thresholds, allowed ports, required services and numeric rules. Custom thresholds replace the stock health thresholds. Plugins are declarative; packs select existing collectors and cannot launch arbitrary commands or read arbitrary files. Examples cover high CPU, disk pressure, exposed ports, SSH and service incidents.

`snapshot --json` stays a flat snapshot, including with policies/packs. Additional evidence is stored in optional `reports`; legacy snapshots remain readable. `report` and extended analysis commands use an analysis envelope. Detailed local snapshots preserve their original default; use `--redact` before sharing. New report formats redact by default and accept explicit `--full`. Bundles and history always redact.

Use `--fail-on info|warning|critical|none` (default `warning`). Required cloud failures set `operationSucceeded=false`; legitimate empty inventories remain successful. Optional service/permission gaps remain warnings unless `--require-complete` is used. Redacted baselines cannot prove exact host, disk, service or listener identity changes: count/state comparisons carry explicit coverage warnings.

### Custody bundles and handoff

```sh
opscope bundle --pack examples/packs/base.yml --evidence security --out incident.zip
opscope verify incident.zip
opscope report baseline.json --bundle incident.zip --format html --out handoff.html --quiet
opscope bundle --out incident.bundle.enc --sign-private-key signer-private.pem --encrypt-public-key recipient-public.pem
opscope verify incident.bundle.enc --public-key trusted-signer.pem --private-key recipient-private.pem
opscope decrypt incident.bundle.enc --private-key recipient-private.pem --out decrypted.zip
```

`bundle` and `offline` create a redacted entry-hash manifest and detached whole-file SHA-256 checksum. Optional RSA-PSS signatures require a separately trusted public key; hashes alone do not authenticate a signer. Optional encryption uses AES-GCM and RSA-OAEP-SHA256. Keys never enter the evidence. Verification bounds archive sizes and validates names, hashes, encryption authentication and supplied signature trust.

A report's `--bundle` option includes the actual file digest and verification result. Native extra evidence requires a fresh local collection; omit `--input` when asking to collect logs or account metadata. Saved evidence remains available to offline reports and analyzers. Platform coverage and supported IoC patterns are documented in [Evidence](src/Opscope.Evidence/README.md).

### Local interface, history and cloud

```sh
opscope serve
opscope serve --history ./private/history.sqlite --retention 100 --retention-days 30
opscope serve --cloud azure,aws --subscriptions <id-a>,<id-b> --profiles account-a,account-b --regions eu-west-1
opscope history list --history ./private/history.sqlite
opscope mcp
opscope azure inventory --subscription <subscription-id>
opscope aws posture --profile audit --region eu-west-1
opscope cloud patches --provider aws --profile audit --region eu-west-1
opscope cloud catalog
opscope gcp inventory --project <project-id>
opscope serve --cloud gcp --gcp-projects <project-id>
```

The embedded English/Spanish UI has light/dark themes, keyboard search, findings, processes/ports, services, drift, observed timeline, history/trends, fleet upload, policy validation/download, cloud connection guidance and verified report/bundle downloads. No assets come from a CDN. Policy editing is preview/download only and never applies host configuration. The server listens only on `127.0.0.1`, on a random port by default. Local mode uses a fresh session token and exact Host/Origin checks. An explicit authenticated reverse-proxy mode binds one public HTTPS origin and keeps its upstream secret outside the browser. Neither mode enables CORS. Full identifiers require an explicit toggle; history and exports stay redacted.

Lightweight CPU/RAM sampling runs every five seconds on Linux, Windows and macOS without enumerating processes for each observation. macOS memory is an estimate based on free and inactive pages, not a memory-pressure score or Activity Monitor equivalent. The first CPU sample, unavailable counters and counter resets remain gaps instead of synthetic zeros.

Drift comparison is enabled only after baseline validation completes. Loading/comparison states prevent premature or duplicate submissions; an older response cannot replace a later selection.

Open **Saved evidence lab / Laboratorio de evidencia** to inspect a complete snapshot JSON, run guided triage, compare recorded observables with CSV/STIX indicators, or build a timeline with an optional saved baseline. The lab keeps its selected evidence separate from the live host and SQLite history; live refresh does not replace the uploaded snapshot or drafts. It exports redacted results and snapshots as JSON, HTML, PDF, SARIF, JUnit, CSV, JSONL or CEF. Tables and findings use bounded pages, and the source bar identifies live, retained, fleet, cloud or uploaded evidence.

Saved analysis and exports accept at most 2 MiB per request; indicator text is limited to 128 KiB. Uploads require strict UTF-8 and complete within ten seconds. Analysis reads recorded evidence only: it does not hash live executables, collect native logs or retrieve remote indicator feeds. A missing IoC match does not establish that a host is safe. Clear the lab to discard its in-memory evidence. [API contracts and limits](src/Opscope.Api/README.md).

CLI commands that analyze `--input` or a saved `report` snapshot reject collection options such as `--cloud-context`, `--evidence` and `--pack`. Live-only modes such as `serve`, `watch`, `tui` and `environment` reject `--input` instead of silently collecting a different host.

For SSH forwarding, preserve the same local and remote port so Host/Origin checks remain valid: for example, `serve --port 48321` and `ssh -N -L 127.0.0.1:48321:127.0.0.1:48321 user@host`. For a shared server URL, configure an authenticated same-host HTTPS proxy and run `serve --port 48321 --public-origin https://opscope.example.com --proxy-token-env OPSCOPE_PROXY_TOKEN`. The named environment variable must hold the same 64-hex-character upstream secret configured in the proxy; the secret is never an argument or browser token. [Remote hosting setup](docs/remote-hosting.md) covers TLS, authentication and the proxy headers. Prometheus, SSE and HTTP MCP remain protected. Stdio MCP exposes only snapshots/findings. [API details](src/Opscope.Api/README.md).

The **Connections** view reports configured scopes, local credential/tool readiness and the last observed read result. It provides fixed official account/console links and authentication command templates for the Opscope host. It does not run those commands or offer a universal cloud OAuth session. Account creation and backend authentication use the provider's own tools. A remote browser views the host running Opscope; it does not collect the browser machine. One hosted instance shares its configured scopes with its authorized operators, so use separate instances when they need different access.

Cloud reads use a separate bounded gate from local host collection. The UI identifies cached responses without changing their original observation time. Provider quota waits apply to the affected configured scope, leave host collection available and do not start automatic retries. See [UI scheduling, cache and retries](docs/cloud.md#ui-scheduling-cache-and-retries).

Cloud queries require an existing authenticated provider CLI or scoped read-only credential. `cloud catalog` describes eleven infrastructure providers and Kubernetes without contacting those services. Newer adapters remain experimental. DigitalOcean verifies the project before inventory/posture. Inventory retains visible project-member resources and VPCs referenced by them; posture evaluates selected direct/tag firewall membership without exporting tags. A referenced VPC is not an assertion of exclusive project ownership. Selected Cloudflare TLS/DNS/WAF/route checks, Alibaba disk-encryption/security-group configuration, IBM regional VPC/subnet/security-group metadata and Scaleway regional VPC/private-network inventory retain explicit scopes and per-read coverage. IBM networks verifies the selected resource group and account before retaining matching regional resource metadata. These observations do not establish effective reachability or complete security. Google Cloud combines an existing `gcloud` session with ADC for Monitoring/SCC/billing/OS Config reads; bounded GKE node-pool management/autoscaling metadata comes from the existing cluster-list read and does not establish health. Cloud Run retains only the selected ingress annotation; missing ingress and the unavailable v1 update timestamp stay unknown. Billing only reads a preconfigured export table and never creates query jobs or claims a complete bill. Existing OS Config jobs do not prove current patch compliance. Inventory drift requires a compatible explicit private baseline. Kubernetes requires an approved existing context and explicit namespaces; it reads metadata/status and optional Metrics Server observations without Secrets, environment, logs or mutations. An opt-in exact match between node references and scoped GCP/Azure inventory verifies only that reference, not cluster ownership. Metrics preserve source-specific units, such as cumulative CPU, edge counts or Prometheus scrape `up`, instead of treating every source as CPU percentage. See [provider setup, commands and actual coverage](docs/cloud.md). Established Azure/AWS queries retain their CLI behavior with dynamic installation, telemetry/upgrade and interactive prompting disabled. Authentication caches remain under the CLIs' control and are not included in evidence.

Azure/AWS operations are inventory, posture, health, VM/instance context, bundle, drift, patches and cost; Azure also exposes Arc. New adapters advertise only implemented operations; reported machine/zone state and configuration do not prove application health or complete security posture. Multiple scopes are fixed when a UI session starts and appear as anonymous numbered choices. Identity-only IMDS/IMDSv2 lookup occurs only through explicit cloud commands or `--cloud-context`. Local-to-cloud identity is asserted only when metadata matches the selected resource; SSM service state never proves cloud Online status. No agent or paid service is enabled.

See the [v4 engineering implementation matrix](docs/engineering-review-v4.md), [cloud commands, permissions and limits](docs/cloud.md), [Azure drift formats](docs/azure-drift.md), and the [read-only AWS IAM policy example](docs/cloud-readonly-iam.json). Raw Bicep/HCL is not executed; use compiled ARM or supported Terraform JSON. Cost evidence is observational and does not delete/resize resources or promise savings.

`notify` previews bounded redacted summaries for Slack, Teams, Jira, Azure DevOps, Azure Monitor or CloudWatch. Only `--confirm-send` enables delivery to an existing destination with separately supplied credentials. Neither local collection nor the web UI sends notifications. [Delivery and release setup](docs/delivery.md).

For ASFF import, supply `--format asff --account <12-digit-id> --region <region>`. Generic library ASFF without context is explicitly marked as an offline placeholder.

### Validation and packaging

```sh
dotnet build src/Opscope/Opscope.csproj -c Release
# Run every tests/*/*.csproj regression project.
python3 tests/cli_smoke.py
python3 -m unittest discover -s packaging -p 'test_*.py'
dotnet pack src/Opscope/Opscope.csproj -c Release -p:PublishSingleFile=false -o artifacts/tool
```

CI runs .NET checks on Linux/Windows/macOS and Playwright on Linux/Windows, then builds and verifies candidate packages through the reusable package workflow. Matching host architectures exercise the published executable; cross-built architectures are checked as artifacts without claiming native execution. Provider, identity and notification tests use injected transports, with no live tenant/account, real messages or infrastructure changes. Package tooling creates six-RID archives, actual-output SBOMs/checksums and winget/Homebrew manifests derived from real artifact hashes. Release-only signing/provenance uses configured credentials. Public releases and package-registry submission remain separate actions; unsigned artifacts are not labelled signed.

Key code comments use **EN/ES** to explain trust boundaries, evidence provenance and concurrency. Public identifiers, CLI flags and JSON schemas keep their existing names. See the [dependency review / revisión de dependencias](docs/dependency-review.md) for the reviewed updates, compatibility checks and native SQLite version change.

The [proposal matrix](docs/proposals.md) maps all 60 items to code, supported scopes and explicit limitations. The recommended local web interface was selected; optional native-window alternatives are not required to run it. Review operational evidence before sharing it.
