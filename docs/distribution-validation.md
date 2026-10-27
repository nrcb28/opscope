# Verificación de distribución

La distribución continúa desde `52e2b66a8e76836fe3890bbe672944c4070bcbbf`, después de las mejoras cloud, Kubernetes e interfaz. La validación de cuentas cloud y clústeres reales queda aplazada; las comprobaciones de paquetes no necesitan esas identidades.

El [workflow de paquetes](../.github/workflows/package-build.yml) se reutiliza desde CI y desde la preparación de releases. La variante de CI usa permisos de lectura, no recibe certificados de firma y entrega una versión candidata identificada por el número de ejecución. Las firmas y atestaciones pertenecen al flujo de release y requieren su configuración correspondiente.

## Verificación local

Comprobación del 27 de octubre de 2026 en Linux x64, con la candidata local `0.2.0-ci.1`. Se utilizaron los archivos producidos por `dotnet publish` y `dotnet pack`, incluidos sus SBOM y manifiestos; las consultas cloud permanecieron desactivadas.

| Comprobación | Resultado |
| --- | --- |
| Compilación autocontenida | Construidos los seis RIDs: Linux, Windows y macOS, cada uno en x64/arm64. |
| Integridad del conjunto | Verificados seis archivos de distribución binaria y un paquete `dotnet tool`, con 60 archivos de publicación inventariados, 128 entradas de archivo y 19 archivos cubiertos por checksums. |
| Ejecutable Linux x64 extraído | 19 pruebas CLI aprobadas con el SDK fuera del `PATH` y `DOTNET_ROOT` apuntando a una ubicación inexistente. |
| Herramienta instalada desde el paquete local | 19 pruebas CLI aprobadas; desinstalación confirmada para `0.2.0-ci.1`. |
| CLI compilada desde fuente | 19 pruebas aprobadas. |
| Herramientas Python de empaquetado | 31 pruebas aprobadas de versiones, archivos, metadatos, integridad y rechazo de entradas incompatibles. |
| Sintaxis de workflows | `actionlint` aprobado. |

Los otros cinco RIDs recibieron compilación y verificación de archivos en esta sesión, sin ejecución nativa local. La comprobación de firma del editor permanece en `false`: esta candidata no se presenta como firmada ni notarizada.

La ejecución de CI remoto de esta revisión queda pendiente de la publicación de la PR. Los resultados de regresión de fases anteriores permanecen en [la verificación v4](engineering-review-v4-validation.md) y no sustituyen las pruebas anteriores de los paquetes.

La verificación distingue compilación de seis arquitecturas, integridad de archivos y ejecución nativa en arquitecturas coincidentes con el runner. El paquete `dotnet tool` requiere el runtime ASP.NET Core de .NET 8; los archivos autocontenidos incluyen su runtime. Los artefactos de CI caducan a los catorce días. Una descarga de workflow no equivale a una release pública, una firma nativa ni una publicación en NuGet, winget o Homebrew.
