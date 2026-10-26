# Auditoría de ingeniería v4: implementación y límites

Esta entrega aplica la auditoría ampliada de interfaz, streaming y multicloud del 25 de octubre de 2026 sobre la base `117de2a`. El PDF contiene un diseño propuesto y un backlog de 106 tareas; no es una certificación ni una medición de producción. Los estados siguientes describen código comprobable y separan la implementación de las comprobaciones que necesitan identidades, sistemas operativos o servicios reales. El inventario anterior de 60 requisitos permanece en [proposals.md](proposals.md).

## Uso inmediato / Quick start

```sh
dotnet build src/Opscope/Opscope.csproj -c Release
opscope serve
opscope cloud catalog
opscope gcp inventory --project <project-id>
opscope serve --cloud gcp --gcp-projects <project-id>
```

Con una compilación desde fuente, utiliza `dotnet run --project src/Opscope --` en lugar de `opscope`. `serve` funciona sin credenciales cloud. El catálogo enumera capacidades locales sin consultar cuentas; una capacidad registrada no demuestra autenticación ni disponibilidad de un ámbito. [Configuración, permisos y cobertura por proveedor](cloud.md).

The local dashboard and aggregate host sampler work without cloud credentials. The provider catalog is local metadata; cloud actions use only the scopes fixed when the server starts. New adapters are experimental and carry explicit coverage warnings. Missing permissions, unsupported metrics and incomplete inventory never become a healthy state or a zero metric.

## Decisiones de arquitectura

- La UI conserva JavaScript, HTML y CSS nativos embebidos. El módulo de gráficas es un recurso local conocido; no incorpora framework, CDN ni script remoto.
- Una conexión SSE autenticada transporta eventos `snapshot` y `metrics`. El token permanece en cabecera y memoria; no se añade a URLs de métricas. El servidor mantiene los controles de loopback, Host/Origin, concurrencia y tiempos de escritura.
- El muestreo agregado se separa del snapshot completo. Un temporizador por servidor lee CPU/RAM cada cinco segundos sin enumerar procesos, servicios o sockets en cada muestra.
- El registro de proveedores es cerrado y describe operaciones reales. Las acciones web quedan vinculadas a ámbitos configurados en el servidor y usan alias anónimos; el navegador no elige endpoints, credenciales o cuentas arbitrarias.
- Azure/AWS conservan sus CLI existentes. Google Cloud combina la sesión existente de `gcloud` para inventario/estado con ADC para Monitoring. Cinco adaptadores adicionales usan rutas HTTPS fijas; los demás usan CLI existentes con comandos y opciones de lectura permitidos. Ninguna consulta instala agentes o activa servicios.

## Métricas de host y gráfica

El contrato versionado incluye secuencia monótona, UTC, tiempo transcurrido, intervalo, CPU/memoria anulables, origen y cobertura. La primera lectura CPU calienta el contador y queda ausente; un reinicio de contador, error o plataforma sin soporte no genera un cero. Linux usa `/proc/stat` y `/proc/meminfo`; Windows usa `GetSystemTimes` y `GlobalMemoryStatusEx`. En macOS estas métricas ligeras quedan no disponibles mientras los snapshots completos conservan su cobertura propia.

La retención es un anillo de hasta 720 observaciones en memoria de sesión, sin identificadores de host, usuario, proceso, interfaces, rutas o credenciales. No escribe estas muestras en SQLite. La secuencia y el reloj monótono ordenan las observaciones aunque cambie UTC; `clockAdjusted` marca los saltos del reloj. No se inventan series de disco, red, CPU de proceso o nube.

`GET /api/metrics/capabilities` anuncia el soporte. `GET /api/metrics/history?window=15m&limit=720&afterSequence=0` devuelve solo datos retenidos; acepta ventanas `5m`, `15m`, `30m` o `1h`, un límite de 1–720 y un cursor no negativo. Rechaza campos desconocidos/repetidos. Ambos endpoints requieren la sesión local. SSE comunica `metrics-gap` cuando un cliente pierde observaciones; no promete un replay de snapshots.

La gráfica distingue muestras ligeras de snapshots, ofrece ventanas de 5/15/30 minutos, pausa/reanudación, reducción por píxel conservando mínimos/máximos, huecos y antigüedad visibles y una tabla accesible de puntos. Las métricas cloud conservan su periodo, unidad, agregación y hora del proveedor y se presentan separadas de las métricas locales.

## Cobertura del backlog de UI y Google Cloud

«Aplicado» identifica una implementación local; «parcial» conserva un criterio del PDF fuera del alcance real. Las pruebas y los checks de la revisión concreta establecen qué plataformas y escenarios se ejecutaron.

| IDs del PDF | Implementación | Límite verificable |
| --- | --- | --- |
| UI-101, TEST-101 | Pruebas de UI con fixtures, temas, resoluciones, privacidad y accesibilidad automatizada. | La revisión manual a 200% y con lectores de pantalla se realiza en los entornos correspondientes; no se afirma un resultado universal de todas las combinaciones. |
| UI-102, UI-103 | Tokens/legibilidad, navegación agrupada, menú móvil con estado y Escape, foco de navegación. | La adaptación conserva doce vistas y los recursos embebidos. |
| UI-104, UI-106 | Fuente, edad, recuperación, ausencia de datos y cobertura explícitas. | Ausencia de hallazgos no certifica seguridad ni salud. |
| UI-105 | Se conservan las barreras full/redacted, exportación redactada y estados aislados del laboratorio. | La evidencia completa y el token no se persisten en almacenamiento del navegador. |
| UI-107, UI-120, UI-124, UI-125 | DTO versionado, anillo acotado, sampler ligero y capacidades/historial autenticados. | CPU/RAM ligeras disponibles en Linux/Windows; sin muestreo inventado en otros sistemas. No hay benchmark de coste válido para cada equipo/SO. |
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
| GCP-101, GCP-102, GCP-103, GCP-105 | Registro GCP, ámbitos explícitos, inventario acotado, cobertura y Cloud workspace con once proveedores. | Asset Search cubre tipos seleccionados; la visibilidad IAM y la frescura del proveedor limitan la enumeración. |
| GCP-104, GCP-106, GCP-107 | Monitoring CPU mediante ADC con HTTPS fijo/acotado, sin redirects y fixtures de errores/series. | Ventana fija de quince minutos, medias de sesenta segundos; necesita ADC y permisos Monitoring reales. No hay latencia ni disponibilidad de aplicación inferidas. |
| GCP-108 | Parcial: metadatos Asset Search de GKE/Cloud SQL/Cloud Run. | No equivale a adaptadores completos de salud, IAM o métricas específicos de cada servicio. |
| GCP-109, GCP-110 | No implementados: SCC y facturación BigQuery. | No se inventan findings/costes ni se ejecutan jobs de facturación. |
| TEST-102 | Benchmark DOM reproducible con 1.000 procesos y 500 hallazgos, tres calentamientos y veinte iteraciones de navegación/ordenación. | `npm run benchmark` registra P95 y entorno sin un umbral universal; los resultados se comparan en la misma máquina. Se montan como máximo 50 filas/tarjetas en la configuración inicial. |
| DOC-101 | Guías de permisos, límites, decisiones y ejemplos ES/EN actualizados. | Firma nativa, registros de paquetes y servicios de pago requieren su configuración real. |

## Cobertura de las 64 tareas multicloud

| IDs | Resultado de esta implementación | Criterios restantes |
| --- | --- | --- |
| CLOUD-201–204 | Contratos de descriptor, enum de operaciones/cobertura, catálogo autenticado y registro cerrado con ámbitos de sesión anónimos. | Readiness describe configuración y última observación; no descubre permisos sin ejecutar una acción. |
| CLOUD-205–207 | Transporte HTTPS de host/ruta fijos, redirects deshabilitados, límites de bytes/páginas/profundidad y credenciales solo del backend. | No se añade un secret store general ni una UI de autenticación. Los endpoints privados OpenStack proceden del `clouds.yaml` del administrador. |
| CLOUD-208 | Protección de concurrencia/tiempos por acción de sesión; respuestas de saturación y `Retry-After`. | Cuotas de proveedor y semánticas de reintento varían; no se afirma un rate-limit universal compartido entre todos los procesos. |
| CLOUD-209–212 | Workspace guiado por catálogo, estados de cobertura y fixtures de contrato/transporte. | Los fixtures no certifican IAM, disponibilidad ni paginación de todas las cuentas reales. |
| CLOUD-213, CLOUD-214 | Parcial: series GCP/DigitalOcean/Hetzner con periodo/unidad/agregación y gráfica independiente de las muestras locales. | Los otros seis adaptadores nuevos no ofrecen todavía historias de métricas; no se anuncian esas capacidades. |
| CLOUD-215, CLOUD-216 | Guía por proveedor y catálogo de once proveedores usable sin credenciales. | Ejecutar acciones reales exige permisos y servicios previamente configurados. |
| OCI-01–05 | Registro, CLI existente, inventario acotado de instancias/volúmenes/VCN, estado y reglas de security lists. | Las reglas configuradas no prueban conectividad efectiva; cobertura experimental parcial. |
| DO-01–06 | Token de lectura, proyecto explícito, droplets/volúmenes asociados, firewalls por membresía directa y series CPU nativas en segundos acumulados. | La membresía por tags y otros tipos de recursos del proyecto quedan fuera de cobertura. |
| HET-01–06 | Token de proyecto, servidores/volúmenes/redes/load balancers, reglas de firewall e historia CPU acotada. | El label de proyecto es descriptivo; no establece una identidad independiente del token. Las reglas no prueban accesibilidad efectiva. |
| CF-01–05 | Registro, token restringido, cuenta explícita e inventario/estado/configuración paused de zonas. | DNS, WAF, TLS y analytics no se consultan; postura avanzada queda sin implementar. |
| OS-01–05 | CLI existente, proyecto/region/cloud fijados, inventario y reglas de security groups. | Endpoints/CA se administran fuera de Opscope; sin telemetría ni evaluación completa de salud de la nube. |
| ALI-01–05 | Identidad de cuenta explícita, instancias/discos/VPC, estado de ECS y cifrado declarado de discos. | La postura no evalúa security groups ni IAM de cuenta; sin métricas ni visibilidad IAM universal. |
| IBM-01–05 | Token IAM externo, Resource Controller con rutas HTTPS fijas y comprobación de cuenta/resource-group/región para metadatos y estado de servicios. | No consulta VPC, Monitoring ni toda la configuración de cada servicio. No inicia sesión ni renueva el token desde Opscope. |
| SCW-01–05 | Token SCW_SECRET_KEY del servidor, rutas HTTPS fijas y proyecto/zona explícitos para servidores/volúmenes de Instance. | VPC regional, gateways, postura completa y Monitoring quedan fuera de cobertura. |
| OCI-06, CF-06, OS-06, ALI-06, IBM-06, SCW-06 | No implementados: historias opcionales de métricas de esos seis proveedores. | Las operaciones no aparecen como disponibles en el catálogo; ausencia de muestras no es cero. |

Kubernetes transversal y la correlación entre clúster/host/cuenta descritos como MC-4 permanecen fuera de esta entrega. Detectar marcadores locales de contenedor no equivale a consultar la API de un clúster. No se leen Kubernetes Secrets, variables de entorno de pods ni logs remotos.

## Verificación y publicación

El [workflow CI](../.github/workflows/ci.yml) descubre todos los proyectos .NET, ejecuta CLI/smoke y tiene pruebas de navegador Chromium en Linux/Windows. Los proyectos cloud usan transportes inyectados; los checks concretos de cada commit son la evidencia del resultado. No se utilizaron cuentas de producción para afirmar mínimos IAM universales, precios, cuotas o frescura.

La distribución mantiene el [workflow de releases](../.github/workflows/release.yml) y las herramientas de empaquetado existentes. Subir código a GitHub no equivale a publicar una nueva versión firmada en cada registro ni a desplegar un servicio público; la app se sigue ejecutando localmente con `serve`.
