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

Verificación local del 27 de octubre de 2026, sobre la base `3f2ada84bfef7ebb6807235eecad4c2d7eb192eb`. Su alcance y límites se describen en [cloud.md](cloud.md) y en la [matriz de implementación](engineering-review-v4.md). Los resultados siguientes corresponden a Linux x64; la ejecución de CI remoto en Windows, macOS y Linux queda pendiente de publicar esta revisión.

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
