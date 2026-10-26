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
