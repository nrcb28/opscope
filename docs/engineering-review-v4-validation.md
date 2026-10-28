# Verificación de la implementación v4

Revisión del 26 de octubre de 2026, sobre la base `117de2aab5a55748289271604c6a1c06d82f2532`.

La implementación y sus límites se describen en [engineering-review-v4.md](engineering-review-v4.md). Estos resultados se obtuvieron en Linux x64; no equivalen a una certificación de cuentas cloud reales ni a una ejecución local en Windows/macOS.

| Comprobación | Resultado local |
| --- | --- |
| Compilación CLI y módulos, .NET SDK 8.0.426, Release | Aprobada, cero errores y cero advertencias. |
| Proyectos de regresión .NET | Los catorce proyectos aprobados, incluidas las regresiones existentes de Azure, AWS, almacenamiento, evidencia, informes, integración y CLI. |
| API, SQLite y MCP | 289 comprobaciones: sesión/origen, límites, catálogo, estados de cobertura, caché redactada, cursores SSE y métricas. |
| Métricas ligeras | 837 comprobaciones de contadores, retención, orden monótono y privacidad. |
| Proveedores adicionales | 130 comprobaciones con transportes inyectados; ámbitos, errores, unidades, paginación, fechas y límites de métricas. |
| Google Cloud | Inventario y ámbitos, parcialidad, Monitoring ADC, ratio/porcentaje, límites agregados, filtrado de recursos y redacción aprobados con fixtures. |
| Navegador Chromium | 112 comprobaciones: privacidad, descargas, flujos guardados, cobertura cloud, teclado, gráficas, menú móvil y accesibilidad automatizada. |
| Resoluciones y zoom | Sin desbordamiento horizontal entre 320 y 1920 px; reflujo equivalente a 200%; ejes de gráficas legibles en móvil. |
| CLI real, pruebas Python | 17 pruebas aprobadas. |
| Prueba de humo Unix y herramientas de distribución | Aprobadas; seis pruebas de empaquetado aprobadas. |

Para repetir el benchmark opcional, compila el fixture Debug, instala las dependencias bloqueadas y ejecuta `npm run benchmark` en `tests/Opscope.ApiTests`. Genera `test-results/dom-benchmark.json` con entorno, P95 y número de nodos montados. La carga es sintética: 1.000 procesos y 500 hallazgos; no consulta proveedores. No se impone un umbral temporal universal.

Los endpoints cloud reales necesitan las identidades, API y permisos descritos en [cloud.md](cloud.md). No se emplearon cuentas de producción. La revisión manual con lectores de pantalla, las firmas de distribución y las capacidades marcadas como pendientes en la matriz siguen requiriendo su validación o implementación correspondiente.

## Segunda fase: GCP avanzado, métricas y Kubernetes

Verificación local del 27 de octubre de 2026, sobre la base `bb5115846686ee904a2fd47431cc88d1f70d6ab3`. La tabla anterior conserva los resultados históricos de la primera fase. Los resultados siguientes corresponden a la segunda fase en Linux x64. Antes de integrar la [PR #14](https://github.com/nrcb28/opscope/pull/14), también aprobaron las cinco comprobaciones de [CI remoto](https://github.com/nrcb28/opscope/actions/runs/40491327233): regresiones en Windows, macOS y Linux, y navegador en Windows/Linux.

| Comprobación | Resultado local de la segunda fase |
| --- | --- |
| Compilación CLI y módulos, Release | Aprobada, cero errores y cero advertencias. |
| Proyectos de regresión .NET | Los dieciocho proyectos aprobados, incluidos los cuatro proyectos nuevos de GCP avanzado, Kubernetes y métricas adicionales. |
| API, SQLite y MCP | 311 comprobaciones aprobadas; incluyen el catálogo ampliado, la cobertura sin datos y los contratos de SCC, facturación y Kubernetes. |
| Google Cloud avanzado | 51 comprobaciones aprobadas de ámbitos, SCC, facturación, proyecciones de servicios y transportes. |
| Kubernetes | 111 comprobaciones aprobadas de ámbitos, gramática de comandos, metadatos, cantidades de métricas, privacidad y límites. |
| Métricas OCI, OpenStack y Cloudflare | 43 comprobaciones aprobadas de telemetría, identidad, unidades, privacidad y límites. |
| Métricas Alibaba, IBM y Scaleway | 59 comprobaciones aprobadas de ámbitos, unidades, privacidad, transportes y presupuestos de lectura. |
| Métricas ligeras y regresión multicloud | Conservadas: 837 y 130 comprobaciones aprobadas, respectivamente. |
| Navegador Chromium | 125 comprobaciones aprobadas de interfaz y accesibilidad; sin errores de JavaScript ni solicitudes fuera del origen local autenticado. |
| Resoluciones y zoom | Sin desbordamiento horizontal entre 320 y 1920 px; reflujo equivalente a 200%; verificaciones de accesibilidad en temas claro y oscuro. |
| CLI real, pruebas Python | 18 pruebas aprobadas. |
| Prueba de humo Unix y herramientas de distribución | Prueba de humo aprobada; seis pruebas de empaquetado aprobadas. |

Las pruebas de proveedores usan fixtures y transportes inyectados; no se utilizaron cuentas cloud reales ni un clúster remoto. Por tanto, no certifican permisos IAM/RBAC, configuración de ADC, disponibilidad de APIs o Metrics Server, ni compatibilidad con cada despliegue del proveedor. La CI y las lecturas reales requieren sus entornos correspondientes.

El alcance comprobado conserva los límites descritos en [cloud.md](cloud.md): la facturación muestra subtotales incompletos de filas observadas, las métricas mantienen sus unidades originales y Kubernetes no inventa historia para una observación puntual. En esa segunda fase quedaron pendientes la correlación entre clúster e infraestructura, las evidencias OS Config y el drift de Google Cloud. Las firmas de distribución y la revisión manual con lectores de pantalla tampoco formaron parte de esa validación.

## Tercera fase: jobs OS Config, baseline GCP y referencias de nodos

Verificación local del 27 de octubre de 2026, sobre la base `3f2ada84bfef7ebb6807235eecad4c2d7eb192eb`. Su alcance y límites se describen en [cloud.md](cloud.md) y en la [matriz de implementación](engineering-review-v4.md). Los resultados siguientes corresponden a Linux x64. Antes de integrar la [PR #15](https://github.com/nrcb28/opscope/pull/15), también aprobaron las cinco comprobaciones de [CI remoto](https://github.com/nrcb28/opscope/actions/runs/40535447363): regresiones en Windows, macOS y Linux, y navegador en Windows/Linux.

| Comprobación | Resultado local de la tercera fase |
| --- | --- |
| Compilación CLI y módulos, Release | Aprobada, cero errores y cero advertencias. |
| Proyectos de regresión .NET | Los veinte proyectos aprobados, incluidas las nuevas suites de OS Config y baseline GCP. |
| API, SQLite y MCP | 319 comprobaciones aprobadas; incluyen las acciones configuradas de patches y drift, sus límites de evidencia y la redacción. |
| OS Config | 110 comprobaciones aprobadas de identidad, proyección, fechas, contadores desconocidos, errores y presupuestos de lectura. |
| Baseline GCP | 63 comprobaciones aprobadas de ámbitos, cobertura, filtros, entradas redactadas, perfil no admitido y exportación/comparación real con transporte simulado. |
| Kubernetes y referencias de infraestructura | 162 comprobaciones aprobadas; incluyen coincidencias exactas, frescura, referencias ambiguas o no admitidas, opt-in y privacidad. |
| Navegador Chromium | 139 comprobaciones aprobadas de interfaz y accesibilidad, incluidas las nuevas vistas de patches, drift y referencias de nodos; sin errores de JavaScript ni solicitudes fuera del origen local autenticado. |
| Resoluciones y zoom | Verificaciones entre 320 y 1920 px, reflujo equivalente a 200% y accesibilidad en temas claro y oscuro conservadas; tablas nuevas comprobadas en móvil. |
| CLI real, pruebas Python | 19 pruebas aprobadas. |
| Prueba de humo Unix y herramientas de distribución | Prueba de humo aprobada; seis pruebas de empaquetado aprobadas. |

La evidencia OS Config corresponde a jobs ya registrados y no establece cumplimiento actual. La comparación GCP requiere inventarios normalizados privados y compatibles; rechaza perfiles declarados que no seleccionan una identidad GCP. Un enlace de nodo Kubernetes verifica solo su referencia contra el recurso observado; no verifica identidad del controlplane ni propiedad del clúster. Las pruebas usan fixtures y transportes simulados, sin cuentas cloud reales ni clúster remoto. Estas funciones siguen necesitando configuración e identidades reales para validar IAM/RBAC, ADC y disponibilidad de servicios fuera de los fixtures.

## Quinta fase: configuración cloud, conexiones y acceso remoto

La quinta fase parte de `b7c641084dd6ab5de2c5ed1f952f86cc035474e0`, después de la distribución candidata de la [PR #16](https://github.com/nrcb28/opscope/pull/16), cuyos quince trabajos de [CI](https://github.com/nrcb28/opscope/actions/runs/40539617841) aprobaron. Esa distribución es una candidata temporal, con artefactos conservados catorce días; no se presenta como una release pública firmada.

La ampliación incluye el menú Conexiones, su lectura local de preparación y el modo de proxy HTTPS autenticado para usar la UI en un servidor remoto. La verificación local del 28 de octubre de 2026 corresponde a Linux x64. Antes de integrar la [PR #17](https://github.com/nrcb28/opscope/pull/17), aprobaron los quince trabajos de [CI remoto](https://github.com/nrcb28/opscope/actions/runs/40722169608), incluidas regresiones Linux/Windows/macOS, navegador Linux/Windows y generación/verificación de los paquetes candidatos. El alcance y los prerrequisitos por check se describen en [cloud.md](cloud.md), la [matriz de implementación](engineering-review-v4.md) y la [guía de acceso remoto](remote-hosting.md).

| Comprobación | Resultado local de la quinta fase |
| --- | --- |
| Compilación CLI y módulos, Release | Aprobada, cero errores y cero advertencias. |
| Proyectos de regresión .NET | Los veinticinco proyectos aprobados, incluidas las tres suites de configuración cloud y las de conexiones y hosting remoto. |
| API, SQLite y MCP | 331 comprobaciones aprobadas de regresión y contratos, incluidos catálogo, ámbitos y evidencia de configuración. |
| Cloudflare posture | 93 comprobaciones aprobadas de selección de checks, identidad de zona/cuenta, privacidad, errores y presupuestos de lectura. |
| Alibaba posture | 94 comprobaciones aprobadas de STS, proyecciones CLI, cifrado de discos, reglas ingress, parcialidad y límites. |
| Scaleway networks | 78 comprobaciones aprobadas de proyecto/región, VPC/redes privadas, paginación, permisos, observaciones desconocidas y límites. |
| Conexiones cloud | 188 comprobaciones aprobadas de preparación local, enlaces/plantillas fijos, herramientas de confianza, privacidad y estados de la última lectura. |
| Hosting remoto | 115 comprobaciones aprobadas de origen público, loopback, token de upstream, sesión, redacción y errores cloud diferenciados. |
| Navegador Chromium | 177 comprobaciones aprobadas de interfaz y accesibilidad, incluida configuración cloud, Conexiones, conservación de sesión ante errores de proveedor y acceso en modo proxy sin token de upstream en el navegador. |
| CLI real, pruebas Python | 21 pruebas aprobadas, incluidos ámbitos explícitos y rechazo de configuración inválida del proxy antes de recolectar. |
| Humo Unix, gráficas y herramientas de distribución | Prueba de humo y pruebas unitarias de gráficas aprobadas; 31 pruebas de herramientas de empaquetado aprobadas. |

Los tests de proveedores utilizan transportes y respuestas simulados. La validación de cuentas cloud reales permanece aplazada por indicación del usuario; no hay un despliegue remoto activo, un dominio/certificado emitido ni un login real atribuible a estas pruebas. Un ajuste TLS, un agregado DNS/WAF/rutas, una regla ingress o una red privada observados constituyen evidencia de configuración con su ámbito y cobertura; no prueban seguridad completa, acceso efectivo, aislamiento ni salud de aplicación. El menú de conexión no trata la presencia local de credenciales como prueba de permisos y no ejecuta las plantillas de autenticación.

## Sexta fase: concurrencia cloud, caché y métricas ligeras macOS

Esta fase parte de `88e5e91e6364025da243c790228cd922f353dac9`, después de la PR #17. Separa las consultas cloud de la recolección del host, conserva el alcance de las esperas y las fechas de caché, y añade un lector ligero macOS con contadores nativos agregados. La verificación local del 28 de octubre de 2026 corresponde a Linux x64.

| Comprobación | Resultado local de la sexta fase |
| --- | --- |
| Compilación CLI y módulos, Release | Aprobada, cero errores y cero advertencias. |
| Proyectos de regresión .NET | Los veintisiete proyectos aprobados, incluidas las dos nuevas suites de fiabilidad cloud y métricas Darwin. |
| API, SQLite y MCP | 331 comprobaciones aprobadas; conexiones y hosting remoto conservan sus 188 y 115 comprobaciones, respectivamente. |
| Fiabilidad cloud | 2.105 comprobaciones aprobadas de ámbitos cerrados, concurrencia, cuotas por alias, cancelación, privacidad, límites y expiración monótona de caché. Incluye HTTP local/proxy, recolección y SSE durante una consulta bloqueada, y metadatos vinculados a la respuesta original aunque se sustituya la entrada de caché. |
| Métricas Darwin | 178 comprobaciones de ABI, valores válidos/ausentes, overflow, independencia de fuentes, liberación de puertos, estimación de memoria y privacidad con fuentes inyectadas. La lectura nativa real se omite explícitamente en Linux. |
| Navegador Chromium | 200 comprobaciones aprobadas de interfaz y accesibilidad, incluidas 23 nuevas sobre caché, espera por ámbito, disponibilidad del host y memoria estimada. |
| CLI real, pruebas Python | 21 pruebas aprobadas. |
| Humo Unix, gráficas y distribución | Prueba de humo y pruebas unitarias de gráficas aprobadas; 31 pruebas de herramientas de empaquetado aprobadas. |

Las pruebas cloud siguen usando callbacks y transportes simulados, sin cuentas reales ni un despliegue público. Los fixtures nativos comprueban límites, ABI, datos inválidos y errores sin afirmar ejecución local en macOS. El test condicional del sistema real solo aporta evidencia nativa cuando se ejecuta en macOS; publicar un binario de otra arquitectura no sustituye esa ejecución. La memoria macOS es una estimación recuperable y no una lectura de presión de memoria ni una réplica de Activity Monitor. La recolección completa y la serie ligera conservan sus fuentes separadas.
