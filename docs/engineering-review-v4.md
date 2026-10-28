# Auditoría de ingeniería v4: implementación y límites

Esta entrega aplica la auditoría ampliada de interfaz, streaming y multicloud del 25 de octubre de 2026 sobre la base `117de2a`. El PDF contiene un diseño propuesto y un backlog de 106 tareas; no es una certificación ni una medición de producción. Los estados siguientes describen código comprobable y separan la implementación de las comprobaciones que necesitan identidades, sistemas operativos o servicios reales. El inventario anterior de 60 requisitos permanece en [proposals.md](proposals.md).

La segunda fase continúa desde `bb51158`: incorpora lecturas SCC y de exportaciones de facturación existentes, configuración de servicios Google Cloud, métricas opcionales de los seis proveedores restantes y Kubernetes como adaptador de clúster independiente. La cobertura siguiente conserva sus límites de identidad, permisos y datos realmente observados.

La tercera fase continúa desde `3f2ada8`: añade metadatos de jobs OS Config existentes, comparación de inventario GCP con una baseline privada compatible y vínculos exactos entre referencias de nodos Kubernetes y recursos GCP/Azure. Estos vínculos no verifican la identidad del controlplane ni la propiedad del clúster.

La quinta fase continúa desde `b7c6410`, después de la distribución candidata verificada en la [PR #16](https://github.com/nrcb28/opscope/pull/16). Amplía configuración observada de Cloudflare y Alibaba e incorpora inventario regional de redes Scaleway. También añade guías de conexión cloud en la UI y un modo explícito de acceso mediante proxy HTTPS autenticado para un servidor remoto. Las comprobaciones con cuentas reales y el despliegue en un destino remoto siguen sin ejecutarse; las lecturas preservan ámbitos explícitos, estados desconocidos y límites por producto.

La sexta fase continúa desde `88e5e91`, después de la [PR #17](https://github.com/nrcb28/opscope/pull/17). Separa la concurrencia cloud de la recolección del host, añade esperas por ámbito y procedencia temporal de caché, y completa el sampler ligero de macOS con contadores nativos. La memoria macOS conserva su carácter de estimación y las pruebas de cada plataforma delimitan su validación.

## Uso inmediato / Quick start

```sh
dotnet build src/Opscope/Opscope.csproj -c Release
opscope serve
opscope cloud catalog
opscope gcp inventory --project <project-id>
opscope serve --cloud gcp --gcp-projects <project-id>
opscope kubernetes inventory --context <reader-context> --namespaces <namespace>
```

Con una compilación desde fuente, utiliza `dotnet run --project src/Opscope --` en lugar de `opscope`. `serve` funciona sin credenciales cloud. El catálogo enumera capacidades locales sin consultar cuentas; una capacidad registrada no demuestra autenticación ni disponibilidad de un ámbito. [Configuración, permisos y cobertura por proveedor](cloud.md).

The local dashboard and aggregate host sampler work without cloud credentials. The provider catalog is local metadata; cloud actions use only the scopes fixed when the server starts. New adapters are experimental and carry explicit coverage warnings. Missing permissions, unsupported metrics and incomplete inventory never become a healthy state or a zero metric.

## Decisiones de arquitectura

- La UI conserva JavaScript, HTML y CSS nativos embebidos. El módulo de gráficas es un recurso local conocido; no incorpora framework, CDN ni script remoto.
- Una conexión SSE autenticada transporta eventos `snapshot` y `metrics`. En modo local el token permanece en cabecera y memoria del navegador; no se añade a URLs de métricas. En modo proxy el secreto de upstream permanece entre el proxy y Opscope y no se entrega al navegador. El servidor mantiene los controles de loopback, Host/Origin, concurrencia y tiempos de escritura.
- El muestreo agregado se separa del snapshot completo. Un temporizador por servidor lee CPU/RAM cada cinco segundos sin enumerar procesos, servicios o sockets en cada muestra.
- El registro cerrado describe once proveedores de infraestructura y un adaptador Kubernetes de categoría `cluster`. Las acciones web quedan vinculadas a ámbitos configurados en el servidor y usan alias anónimos; el navegador no elige endpoints, credenciales, kubeconfig o cuentas arbitrarias.
- El menú Conexiones separa requisitos locales de credencial/herramienta/ámbito y último acceso observado. Sus enlaces oficiales y plantillas guían la configuración en el host sin ejecutar login, crear cuentas o interpretar una credencial presente como acceso autorizado.
- El límite de consultas cloud es independiente del recolector del host. Las esperas por ámbito y la caché efímera conservan la evidencia original; la UI no confunde una respuesta reutilizada con una nueva lectura ni aplica una cuota cloud al stream o a la recolección local.
- Azure/AWS conservan sus CLI existentes. Google Cloud combina la sesión de `gcloud` para inventario/configuración con ADC para Monitoring, SCC, tablas de facturación y jobs OS Config existentes. Los demás adaptadores utilizan CLI con gramática de lectura fija o rutas HTTPS del proveedor verificadas. Kubernetes usa proyecciones de metadatos/status con un contexto y namespaces explícitos. Ninguna consulta instala agentes o activa servicios.

## Métricas de host y gráfica

El contrato versionado incluye secuencia monótona, UTC, tiempo transcurrido, intervalo, CPU/memoria anulables, origen y cobertura. La primera lectura CPU calienta el contador y queda ausente; un reinicio de contador, error o plataforma sin soporte no genera un cero. Linux usa `/proc/stat` y `/proc/meminfo`; Windows usa `GetSystemTimes` y `GlobalMemoryStatusEx`. macOS usa contadores agregados de Mach para CPU y una estimación de memoria recuperable con páginas libres e inactivas, tamaño de página y memoria física. No ejecuta procesos para estas muestras ni afirma equivalencia con Activity Monitor o presión de memoria. Los snapshots completos conservan su fuente y cobertura propias.

La retención es un anillo de hasta 720 observaciones en memoria de sesión, sin identificadores de host, usuario, proceso, interfaces, rutas o credenciales. No escribe estas muestras en SQLite. La secuencia y el reloj monótono ordenan las observaciones aunque cambie UTC; `clockAdjusted` marca los saltos del reloj. No se inventan series de disco, red, CPU de proceso o nube.

`GET /api/metrics/capabilities` anuncia el soporte. `GET /api/metrics/history?window=15m&limit=720&afterSequence=0` devuelve solo datos retenidos; acepta ventanas `5m`, `15m`, `30m` o `1h`, un límite de 1–720 y un cursor no negativo. Rechaza campos desconocidos/repetidos. Ambos endpoints requieren la sesión local. SSE comunica `metrics-gap` cuando un cliente pierde observaciones; no promete un replay de snapshots.

La gráfica distingue muestras ligeras de snapshots, ofrece ventanas de 5/15/30 minutos, pausa/reanudación, reducción por píxel conservando mínimos/máximos, huecos y antigüedad visibles y una tabla accesible de puntos. Las métricas cloud conservan su periodo, unidad, agregación y hora del proveedor y se presentan separadas de las métricas locales.

## Cobertura del backlog de UI y Google Cloud

«Aplicado» identifica una implementación local; «parcial» conserva un criterio del PDF fuera del alcance real. Las pruebas y los checks de la revisión concreta establecen qué plataformas y escenarios se ejecutaron.

| IDs del PDF | Implementación | Límite verificable |
| --- | --- | --- |
| UI-101, TEST-101 | Pruebas de UI con fixtures, temas, resoluciones, privacidad y accesibilidad automatizada. | La revisión manual a 200% y con lectores de pantalla se realiza en los entornos correspondientes; no se afirma un resultado universal de todas las combinaciones. |
| UI-102, UI-103 | Tokens/legibilidad, navegación agrupada, menú móvil con estado y Escape, foco de navegación. | Las vistas conservan sus recursos embebidos y la navegación por teclado. |
| UI-104, UI-106 | Fuente, edad, recuperación, ausencia de datos y cobertura explícitas. | Ausencia de hallazgos no certifica seguridad ni salud. |
| UI-105 | Se conservan las barreras full/redacted, exportación redactada y estados aislados del laboratorio. | La evidencia completa y el token no se persisten en almacenamiento del navegador. |
| UI-107, UI-120, UI-124, UI-125 | DTO versionado, anillo acotado, sampler ligero Linux/Windows/macOS y capacidades/historial autenticados. | La memoria macOS es una estimación recuperable; primera CPU, errores y reinicios quedan ausentes. No hay benchmark de coste válido para cada equipo/SO ni ejecución nativa de todas las arquitecturas macOS. |
| UI-108, UI-123 | Eventos de métricas sobre la conexión SSE existente, cursor, reconexión y avisos de huecos. | La retención es acotada; una desconexión puede perder observaciones. |
| UI-109 | Las actualizaciones en vivo preservan controles editables y ofrecen aplicar evidencia más reciente. | La aplicación conserva renderizadores nativos; no se reescribe toda la app como una arquitectura de componentes nueva. |
| UI-110 | Errores de autenticación, validación, saturación, servicio y timeout diferenciados. | No se reintentan automáticamente operaciones que puedan generar un artefacto. |
| UI-111, UI-127 | Tabla reutilizable con ordenación, páginas 25/50/100, exportación contextual redactada y preferencia de columna. | Las preferencias son de interfaz; la exportación de tabla se deshabilita con identificadores completos. |
| UI-112 | Filtros por severidad/código/origen, inspección y copia de evidencia redactada. | El número de filas DOM permanece acotado por paginación. |
| UI-113 | Semántica explícita del tiempo CPU acumulado y controles de tabla/procesos. | No se convierte tiempo CPU acumulado en utilización instantánea de proceso. |
| UI-114 | Filtro de servicios y estado desconocido/ausencia de cobertura. | Una lista vacía no se interpreta como todos los servicios saludables. |
| UI-115 | Pasos de análisis sobre evidencia guardada y guardas frente a respuestas obsoletas. | Los borradores y archivos quedan en memoria; no sustituyen la fuente en vivo. |
| UI-116, UI-117 | Contexto temporal y notas de interpretación de drift/flota. | Un delta no indica por sí solo mejora; los outliers no son una clasificación universal de riesgo. |
| UI-118 | Exportes agrupados por uso y comprobación SHA-256 conservada. | Un hash confirma bytes y no autentica al remitente. |
| UI-119 | Gutter de líneas, estado del borrador y validación separada. | El YAML se valida/descarga; no modifica la configuración del host. |
| UI-121, UI-122 | SVG de series con huecos, estado obsoleto y alternativa tabular accesible. | Muestras cloud y locales no comparten una serie de continuidad ficticia. |
| UI-126, UI-128, UI-129 | Densidad de tabla, contador de búsqueda y filtro/inspector del historial. | El historial representa observaciones retenidas; no inventa una hora exacta de cambio o un evento nativo. |
| GCP-101, GCP-102, GCP-103, GCP-105 | Registro GCP, ámbitos explícitos, inventario acotado, cobertura y espacio con once proveedores más Kubernetes separado. | Asset Search cubre tipos seleccionados; la visibilidad IAM y la frescura del proveedor limitan la enumeración. |
| GCP-104, GCP-106, GCP-107 | Monitoring CPU mediante ADC con HTTPS fijo/acotado, sin redirects y fixtures de errores/series. | Ventana fija de quince minutos, medias de sesenta segundos; necesita ADC y permisos Monitoring reales. No hay latencia ni disponibilidad de aplicación inferidas. |
| GCP-108 | Operación `services` con proyecciones exactas de configuración/status de GKE, SQL, Cloud Run y Storage; selección de tipos y región explícita para Run. | Run no expone annotations/ingress ni specs; no se consultan pods, objetos, bases de datos o URLs de servicio. Ready/configuración no prueban disponibilidad o restaurabilidad. |
| GCP-109 | Hallazgos existentes SCC v1 global, vinculados al ID/número del proyecto seleccionado y con lectura ADC acotada. | La edición SCC, los permisos y las páginas observadas limitan la cobertura. Una lista vacía o denegada no demuestra seguridad. |
| GCP-110 | GET de esquema y filas de una tabla de exportación existente, configurada expresamente; subtotales por moneda de las filas leídas. | Sin consultas/jobs ni factura total: `isComplete=false`, filas acotadas, filtros por proyectos autorizados y coste desconocido cuando faltan datos. |
| GCP, ampliación de parches | Metadatos y resultados agregados de jobs OS Config existentes, con ADC y vínculo verificado de proyecto ID/número. | Sin ejecución de parches, scripts ni activación de servicios/agentes; el éxito histórico no prueba cumplimiento actual y `complianceState` permanece desconocido. |
| GCP, ampliación de drift | Comparación explícita de dos inventarios normalizados compatibles, con ámbito/filtros/procedencia exactos; presencia y campos compartidos `region`/`state`. | Solo enumeraciones completas permiten altas/ausencias. Con cobertura parcial se conservan comparaciones de atributos conocidos entre recursos presentes en ambos. No ejecuta IaC ni acepta Terraform/HCL; IDs redactados o baselines antiguas sin procedencia no establecen comparación. |
| TEST-102 | Benchmark DOM reproducible con 1.000 procesos y 500 hallazgos, tres calentamientos y veinte iteraciones de navegación/ordenación. | `npm run benchmark` registra P95 y entorno sin un umbral universal; los resultados se comparan en la misma máquina. Se montan como máximo 50 filas/tarjetas en la configuración inicial. |
| DOC-101 | Guías de permisos, límites, decisiones y ejemplos ES/EN actualizados. | Firma nativa, registros de paquetes y servicios de pago requieren su configuración real. |

## Cobertura de las 64 tareas multicloud

| IDs | Resultado de esta implementación | Criterios restantes |
| --- | --- | --- |
| CLOUD-201–204 | Descriptores, operaciones/cobertura, catálogo autenticado y registro cerrado con ámbitos anónimos; Kubernetes conserva la categoría `cluster`. | Readiness describe configuración y última observación; no descubre permisos sin ejecutar una acción. |
| CLOUD-205–207 | Transporte HTTPS de host/ruta fijos, redirects deshabilitados, límites de bytes/páginas/profundidad y credenciales solo del backend. | No se añade un secret store general ni captura de credenciales en la UI. Los endpoints privados OpenStack proceden del `clouds.yaml` del administrador. |
| CLOUD-208 | Una consulta cloud activa por workspace, separada del recolector local; intervalo mínimo por ámbito, espera local tras cuota y `Retry-After`. La UI conserva el alcance de la espera y las fechas de caché. | La espera tras cuota usa un fallback local de quince segundos; no afirma un plazo del proveedor ni un rate-limit universal entre procesos. No hay reintentos automáticos ni bypass de caché. |
| CLOUD-209–212 | Workspace guiado por catálogo, estados de cobertura, menú Conexiones de preparación local y fixtures de contrato/transporte. | Los fixtures no certifican IAM, disponibilidad ni paginación de todas las cuentas reales. El menú no implementa un OAuth universal ni un almacén de cuentas por usuario. |
| CLOUD-213, CLOUD-214 | Series GCP, DigitalOcean, Hetzner y lectores opcionales OCI/Cloudflare/OpenStack/Alibaba/IBM/Scaleway; Kubernetes ofrece observaciones puntuales de CPU/RAM. | Cada fuente conserva unidad/cadencia: CPU, contadores, tráfico y gauge `up` no se comparan como si fueran la misma métrica. No se inventa historia para puntos aislados. |
| CLOUD-215, CLOUD-216 | Guía de permisos por fuente y catálogo de once proveedores más un adaptador de clúster, consultable sin credenciales. | Ejecutar acciones reales exige permisos y servicios previamente configurados. |
| OCI-01–05 | Registro, CLI existente, inventario acotado de instancias/volúmenes/VCN, estado y reglas de security lists. | Las reglas configuradas no prueban conectividad efectiva; cobertura experimental parcial. |
| DO-01–06 | Token de lectura, proyecto explícito, droplets/volúmenes asociados, firewalls por membresía directa y series CPU nativas en segundos acumulados. | La membresía por tags y otros tipos de recursos del proyecto quedan fuera de cobertura. |
| HET-01–06 | Token de proyecto, servidores/volúmenes/redes/load balancers, reglas de firewall e historia CPU acotada. | El label de proyecto es descriptivo; no establece una identidad independiente del token. Las reglas no prueban accesibilidad efectiva. |
| CF-01–05 | Registro, token restringido, cuenta y zonas explícitas verificadas; postura TLS y metadatos DNS/WAF/Workers-routes seleccionados por check. | Observa configuración y agregados acotados; no evalúa reglas efectivas, tráfico o disponibilidad. Los productos/permisos ausentes quedan desconocidos. Analytics conserva su operación de métricas separada. |
| OS-01–05 | CLI existente, proyecto/region/cloud fijados, inventario y reglas de security groups. | Endpoints/CA se administran fuera de Opscope; Gnocchi es opcional y no equivale a una evaluación completa de salud de la nube. |
| ALI-01–05 | Identidad de cuenta STS explícita, instancias/discos/VPC, estado de ECS, cifrado declarado y lectura acotada de configuración de security groups. | Proyecciones exactas y selección de grupos limitada; una regla de ingress no demuestra accesibilidad efectiva. IAM de cuenta y todos los controles/adjuntos de red permanecen fuera de evaluación. |
| IBM-01–05 | Token IAM externo, Resource Controller HTTPS fijo y comprobación de cuenta/resource-group/región para metadatos y estado de servicios. | No consulta VPC ni toda la configuración de cada servicio; Monitoring solo se consulta mediante la operación opcional de métricas. No inicia sesión ni renueva tokens. |
| SCW-01–05 | Token SCW_SECRET_KEY del servidor y rutas fijas; proyecto/zona para Instance, proyecto/región explícitos para `networks` de VPC/redes privadas con identidad verificada. | Gateways, load balancers y postura completa quedan fuera de cobertura; configuración no prueba aislamiento/conectividad. Cockpit requiere su fuente y token existentes. |
| OCI-06 | Monitoring `oci_computeagent` CPU, porcentaje medio de 60 segundos en el compartimento/región explícitos. | Sin recorridos de subcompartimentos; agentes, IAM y límites pueden dejar cobertura parcial o sin datos. |
| CF-06 | GraphQL de lectura fijo para requests/bytes/cache en zonas cuya cuenta coincide, con buckets de cinco minutos. | Son contadores de edge, no CPU ni una prueba de disponibilidad. Requiere zonas explícitas y permisos Analytics. |
| OS-06 | Búsqueda Gnocchi de recursos del proyecto verificado y lectura de medidas con unidades nativas. | El contador CPU acumulado permanece en nanosegundos; no se convierte en utilización instantánea. Requiere el plugin y telemetría existentes. |
| ALI-06 | CloudMonitor CPUUtilization de instancias ECS verificadas en cuenta/región, máximo diez recursos y periodo solicitado de 60 segundos. | Se conserva el periodo realmente devuelto por el proveedor; las instancias y muestras omitidas por los límites quedan declaradas como cobertura parcial. |
| IBM-06, SCW-06 | Prometheus `up` en instancia Monitoring/fuente Cockpit verificadas, con proyecto/cuenta y URL de proveedor restringidos. | Gauge de scrape 0/1; no es CPU de VM ni salud de aplicación. No se crean fuentes, ingestión ni credenciales. |

MC-4 incorpora Kubernetes como fuente separada, con contexto kubeconfig aprobado, namespaces obligatorios, proyecciones de metadatos/status de cargas/servicios/eventos y observaciones Metrics Server en millicores/bytes. Los nodos son un opt-in separado. Con `--infrastructure-provider gcp|azure`, la referencia canónica `providerID` de un nodo puede contrastarse con el inventario normalizado del proveedor en ámbitos explícitos fijados en backend. La coincidencia verifica solo esa referencia de nodo: la identidad del controlplane y la propiedad del clúster permanecen **no verificadas**, y no se infieren por nombres. Las referencias AWS sin vínculo independiente de cuenta permanecen sin verificar. No se leen Secrets, variables de entorno/commands de pods, ConfigMaps, mensajes de eventos o logs remotos, y no se aplican recursos RBAC desde Opscope.

## Conexiones y acceso a un servidor remoto

`GET /api/cloud/connections` es una lectura autenticada de preparación local y del último resultado de las acciones configuradas. No consulta proveedores ni ejecuta procesos de autenticación. La UI permite abrir los enlaces oficiales de alta/consola y leer los pasos de configuración; las identidades CLI, ADC y los tokens se preparan en el host donde corre Opscope. Los errores de configuración, permisos, cuota y timeout cloud se conservan separados del rechazo de la propia sesión de Opscope.

El modo `serve --public-origin https://dominio --proxy-token-env <variable>` exige un proxy HTTPS autenticado en el mismo host y un secreto de upstream externo de 64 caracteres hexadecimales. Kestrel permanece en loopback, el origen público es explícito y el navegador no recibe ese secreto. La [guía de acceso remoto](remote-hosting.md) incluye el proxy, su autenticación y la alternativa SSH. Todos los operadores autorizados de una instancia comparten sus ámbitos; los usuarios con accesos distintos requieren instancias separadas. Este trabajo prepara y prueba el modo remoto, sin afirmar un despliegue activo, un dominio/certificado emitido o una cuenta cloud autenticada.

## Verificación y publicación

El [workflow CI](../.github/workflows/ci.yml) descubre todos los proyectos .NET, ejecuta CLI/smoke y tiene pruebas de navegador Chromium en Linux/Windows. Los proyectos cloud usan transportes inyectados; los checks concretos de cada commit son la evidencia del resultado. No se utilizaron cuentas de producción para afirmar mínimos IAM universales, precios, cuotas o frescura.

La distribución mantiene el [workflow de releases](../.github/workflows/release.yml) y las herramientas de empaquetado existentes. Subir código a GitHub no equivale a publicar una nueva versión firmada en cada registro ni a desplegar un servicio público. `serve` se ejecuta en el host elegido; el acceso remoto requiere configurar el proxy o el túnel documentados.
