# Dependency review / Revisión de dependencias

Base: `af947ca3b3fa43c7c61785974e114dbb18074b01`.

EN: These updates were reviewed individually against current main and tested together before integration. Major package numbers alone do not establish framework incompatibility. Runtime APIs, native assets, action inputs and permissions were checked separately.

ES: Las actualizaciones se revisaron por separado sobre main y se probaron juntas antes de integrarlas. Una versión mayor del paquete no demuestra por sí sola una incompatibilidad de framework. Se comprobaron por separado las API, los recursos nativos y las entradas y permisos de las acciones.

| PR | Update / Actualización | Compatibility / Compatibilidad |
| --- | --- | --- |
| [#5](https://github.com/nrcb28/opscope/pull/5) | `attest-build-provenance` 4.2.2 | Existing inputs and permissions remain valid with registry upload disabled. / Las entradas y permisos siguen siendo válidos sin subida al registro. |
| [#6](https://github.com/nrcb28/opscope/pull/6) | `download-artifact` 8.0.2 | Compatible with upload-artifact v7 and the existing name/merge options. / Compatible con upload-artifact v7 y las opciones actuales de nombre y combinación. |
| [#7](https://github.com/nrcb28/opscope/pull/7) | Playwright 1.64.1 | Node 22/24 and the bundled Chromium 156 pass the unchanged 74-check browser suite. / Node 22/24 y Chromium 156 incluido superan las 74 comprobaciones sin modificar las pruebas. |
| [#8](https://github.com/nrcb28/opscope/pull/8) | Microsoft.Data.Sqlite 10.0.14 | Provides net8 assets; no .NET target migration is needed. / Incluye ensamblados net8; no requiere migrar el framework. |
| [#9](https://github.com/nrcb28/opscope/pull/9) | SQLitePCLRaw bundle 3.0.5 | Standalone and combined storage, privacy, package-install and CLI checks pass. / Supera pruebas individuales y conjuntas de almacenamiento, privacidad, instalación y CLI. |
| [#10](https://github.com/nrcb28/opscope/pull/10) | YamlDotNet 18.1.0 | The changed custom type-inspector APIs are unused; application YAML limits still apply. / No se usan las API de inspección de tipos modificadas; se conservan los límites YAML de la aplicación. |

## SQLite native version / Versión nativa de SQLite

EN: Bundle 3.0.5 contains native SQLite **3.53.4**, whereas the previous 2.1.14 bundle contained **3.54.0**. This is a lower native engine version despite the larger managed-package number. Review found no known reintroduced SQLite vulnerability or use of a 3.54-only SQL feature in Opscope. Both SQLite PRs were tested independently and together with SDK 8.0.426: 245 API/storage/privacy assertions, actual native-version queries, tool package installation and 15 CLI checks passed. All six release runtime identifiers retain native assets. Cross-platform execution is checked by CI; this does not claim every upstream SQLite feature was tested.

ES: El bundle 3.0.5 contiene SQLite nativo **3.53.4**, mientras que el bundle 2.1.14 anterior contenía **3.54.0**. La versión del motor es menor aunque aumente la versión del paquete administrado. No se encontró una vulnerabilidad conocida reintroducida ni uso en Opscope de SQL exclusivo de 3.54. Ambas PR de SQLite se probaron por separado y juntas con el SDK 8.0.426: pasaron 245 comprobaciones de API/almacenamiento/privacidad, consultas de versión nativa, instalación del paquete y 15 pruebas CLI. Los seis identificadores de runtime conservan recursos nativos. CI comprueba la ejecución multiplataforma; no se afirma que se hayan probado todas las funciones de SQLite.

## Verification / Verificación

EN: Integration uses the existing Linux/Windows/macOS .NET and CLI matrix and Linux/Windows Chromium jobs. Local checks also cover YAML depth, scalar/node/byte limits, tags/anchors/duplicates, malformed Unicode, packaging and workflow lint. Action metadata and pinned commit/tag mappings were reviewed. No release, real OIDC attestation, registry publication, cloud query or external notification was initiated for this review.

ES: La integración usa la matriz existente de .NET y CLI en Linux/Windows/macOS y Chromium en Linux/Windows. Las pruebas locales también cubren profundidad YAML, límites de escalares/nodos/bytes, etiquetas/anclas/duplicados, Unicode inválido, empaquetado y lint de workflows. Se revisaron los metadatos de las acciones y la correspondencia entre tags y commits fijados. Esta revisión no inició releases, atestaciones OIDC reales, publicaciones en registros, consultas cloud ni notificaciones externas.
