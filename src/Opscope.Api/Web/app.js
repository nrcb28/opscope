'use strict';
// EN: Session tokens and evidence stay in memory; only language/theme preferences may persist.
// ES: Los tokens de sesión y la evidencia permanecen en memoria; solo se guardan idioma y tema.
(() => {
const $ = id => document.getElementById(id);
const token = new URLSearchParams(location.hash.slice(1)).get('token');
history.replaceState(null, '', location.pathname);
const words = {
en: {skip:'Skip to evidence',local:'LOCAL',connecting:'Connecting…',connected:'Local session',disconnected:'Session disconnected',readonly:'READ ONLY',redacted:'Identifiers redacted · No telemetry · Loopback only',full:'Show full identifiers',fullWarning:'Full identifiers visible in this session · History and exports remain redacted',workspace:'EVIDENCE WORKSPACE',overview:'Overview',findings:'Findings',processes:'Processes & ports',services:'Services',fleet:'Fleet comparison',fleetUpload:'Upload fleet snapshots',fleetCompare:'Compare fleet',fleetLocal:'Only local processing: snapshots are validated on this loopback session and are never sent to a cloud service or saved in history. Results always redact host identities.',fleetLimit:'Choose 2–100 JSON snapshots, up to 2 MiB total. Distinct host identities or distinct local pseudonyms are required; generic redacted labels cannot identify separate hosts.',fleetSelected:'snapshots selected',fleetEmpty:'Select saved snapshots from at least two hosts to compare their latest observations.',fleetInvalid:'Fleet files must contain valid snapshots with distinct host identities and fit within the 2 MiB total request limit.',fleetHosts:'Distinct hosts',fleetSnapshots:'Snapshots',fleetMedianCpu:'Median CPU',fleetMedianMemory:'Median memory',fleetMedianDisk:'Median disk use',fleetFindings:'Fleet findings',fleetOutliers:'Observed outliers and peer differences',failedServices:'Failed services',drift:'Drift comparison',history:'History & timeline',cloud:'Cloud',policy:'Policy',reports:'Reports & bundle',settings:'Settings',sideNote:'Local evidence. Clear decisions.',readOnlyNote:'No host changes are available.',observability:'HOST OBSERVABILITY',description:'A clear view of this host, from the evidence it provides.',collect:'Collect now',collecting:'Collecting…',search:'Search all evidence',footer:'Evidence stays on this device.',cpu:'CPU utilization',memory:'Memory utilization',disk:'Highest disk use',listeners:'Listening sockets',sample:'Observed sample',diskCount:'ready volumes',exposed:'wildcard listeners',priority:'Prioritized findings',allFindings:'View all findings',host:'Host evidence',platform:'Platform',os:'Operating system',uptime:'Uptime',privilege:'Privilege',elevated:'Elevated',standard:'Standard',processors:'Processors',firewall:'Firewall',verified:'Verified protection',unverified:'Unverified / unknown',warnings:'Collection warnings',noWarnings:'No collection warnings reported.',noFindings:'No findings in this evidence sample.',noData:'No evidence available.',trend:'Local resource history',trendNote:'Samples retained in the redacted SQLite history.',needHistory:'A trend needs at least two retained samples.',severity:'Severity',all:'All severities',critical:'Critical',warning:'Warning',info:'Information',evidence:'Evidence',recommendation:'Suggested remediation',code:'Code',name:'Name',pid:'PID',user:'User',workingSet:'Memory (MiB)',cpuTime:'CPU time',command:'Command line',protocol:'Protocol',address:'Local address',process:'Process',source:'Source',state:'State',serviceDescription:'Description',noRows:'No matching records in this sample.',processList:'Processes by memory',portList:'Listening ports',sort:'Sort processes by',memorySort:'Memory',nameSort:'Name',cpuSort:'CPU time',baseline:'Baseline',current:'Current evidence',upload:'Upload a snapshot JSON',uploadNote:'Maximum 2 MiB. Compared in memory; uploaded data is never stored.',compare:'Compare with current',selectHistory:'Use retained baseline',choose:'Choose a snapshot…',noBaseline:'Select a retained snapshot or upload a baseline to compare.',significant:'Significant changes detected',noSignificant:'No significant changes detected',metric:'Metric',delta:'Delta',changes:'Entity changes',category:'Category',identity:'Identity',change:'Change',details:'Details',retained:'Retained samples',boot:'Observed host boot',historyNote:'Timeline includes observed boot and snapshot collections. Native log events are available through the CLI timeline collector.',sampleFindings:'findings',viewSample:'View redacted sample',redactedSample:'Retained redacted evidence',cloudUnavailable:'No cloud queries are configured for this session. Use the CLI Azure or AWS commands with a configured read-only identity.',run:'Run read-only query',cloudNote:'Cloud queries use the configured shared provider. No credentials or commands can be entered here.',policyUnavailable:'No policy file is configured. The draft below can still be validated and previewed against current evidence.',policyNote:'Policy preview only. Edit a draft, validate it against current evidence, and download the YAML. This never applies policy or changes host configuration.',policyChanged:'Draft changed. Validate again to refresh findings.',policyDraft:'Draft policy YAML',previewPolicy:'Validate & preview',downloadPolicy:'Download validated YAML',policyValid:'Policy validated',policyInvalid:'Policy validation failed',configuredPolicy:'Configured policy view',observedTimeline:'Observed timeline',downloadChecksum:'Download bundle checksum',downloadBundle:'Download redacted bundle',downloadJson:'Download redacted JSON',downloadReport:'Download HTML report',downloadPdf:'Download PDF',downloadSarif:'Export findings as SARIF',printReport:'Print / save as PDF',reportNote:'All exports use shared redaction. Bundle includes its evidence manifest; download its checksum after the ZIP. The Print action opens the browser print dialog.',settingsNote:'Session settings are read only. Tokens are kept in memory and are never written to history.',setting:'Setting',value:'Value',noToken:'Open the complete bootstrap URL printed by opscope serve to start a local session. Reloading requires that URL again.',error:'The local request could not complete.',busy:'The local request is busy or rate limited. Try again shortly.',collected:'Collected',searchEmpty:'No matching evidence.',maxFile:'Choose a JSON file smaller than 2 MiB.',invalidFile:'The uploaded snapshot is invalid or exceeds the supported bounds.',live:'Live evidence',duration:'Collection duration',available:'available',unknown:'Unknown',days:'days',changed:'changed',comparisonReady:'Baseline loaded. Compare it with current evidence.',refreshError:'Live updates paused; reconnecting…'},
es: {skip:'Saltar a la evidencia',local:'LOCAL',connecting:'Conectando…',connected:'Sesión local',disconnected:'Sesión desconectada',readonly:'SOLO LECTURA',redacted:'Identificadores redactados · Sin telemetría · Solo loopback',full:'Mostrar identificadores completos',fullWarning:'Identificadores completos visibles en esta sesión · Historial y exportaciones redactados',workspace:'ESPACIO DE EVIDENCIA',overview:'Resumen',findings:'Hallazgos',processes:'Procesos y puertos',services:'Servicios',fleet:'Comparación de flota',fleetUpload:'Cargar snapshots de flota',fleetCompare:'Comparar flota',fleetLocal:'Solo procesamiento local: los snapshots se validan en esta sesión loopback y nunca se envían a la nube ni se guardan en el historial. Los resultados siempre redactan los hosts.',fleetLimit:'Elige entre 2 y 100 snapshots JSON, hasta 2 MiB en total. Se necesitan identidades o seudónimos locales distintos; las etiquetas redactadas genéricas no identifican hosts separados.',fleetSelected:'snapshots seleccionados',fleetEmpty:'Selecciona snapshots guardados de al menos dos hosts para comparar sus observaciones más recientes.',fleetInvalid:'Los archivos deben contener snapshots válidos de hosts distintos y cumplir el límite total de 2 MiB.',fleetHosts:'Hosts distintos',fleetSnapshots:'Snapshots',fleetMedianCpu:'Mediana de CPU',fleetMedianMemory:'Mediana de memoria',fleetMedianDisk:'Mediana de uso de disco',fleetFindings:'Hallazgos de flota',fleetOutliers:'Valores atípicos y diferencias observadas',failedServices:'Servicios fallidos',drift:'Comparación de drift',history:'Historial y cronología',cloud:'Nube',policy:'Políticas',reports:'Informes y bundle',settings:'Configuración',sideNote:'Evidencia local. Decisiones claras.',readOnlyNote:'No hay acciones que cambien el host.',observability:'OBSERVABILIDAD DEL HOST',description:'Una visión clara de este host, basada en la evidencia disponible.',collect:'Recopilar ahora',collecting:'Recopilando…',search:'Buscar en toda la evidencia',footer:'La evidencia permanece en este dispositivo.',cpu:'Uso de CPU',memory:'Uso de memoria',disk:'Mayor uso de disco',listeners:'Sockets de escucha',sample:'Muestra observada',diskCount:'volúmenes disponibles',exposed:'escuchas en todas las interfaces',priority:'Hallazgos prioritarios',allFindings:'Ver todos los hallazgos',host:'Evidencia del host',platform:'Plataforma',os:'Sistema operativo',uptime:'Tiempo activo',privilege:'Privilegios',elevated:'Elevados',standard:'Estándar',processors:'Procesadores',firewall:'Firewall',verified:'Protección verificada',unverified:'Sin verificar / desconocido',warnings:'Avisos de recopilación',noWarnings:'No se notificaron avisos de recopilación.',noFindings:'No hay hallazgos en esta muestra.',noData:'No hay evidencia disponible.',trend:'Historial local de recursos',trendNote:'Muestras conservadas en el historial SQLite redactado.',needHistory:'Una tendencia necesita al menos dos muestras conservadas.',severity:'Severidad',all:'Todas las severidades',critical:'Crítico',warning:'Advertencia',info:'Información',evidence:'Evidencia',recommendation:'Remediación sugerida',code:'Código',name:'Nombre',pid:'PID',user:'Usuario',workingSet:'Memoria (MiB)',cpuTime:'Tiempo CPU',command:'Línea de comandos',protocol:'Protocolo',address:'Dirección local',process:'Proceso',source:'Origen',state:'Estado',serviceDescription:'Descripción',noRows:'No hay registros coincidentes en esta muestra.',processList:'Procesos por memoria',portList:'Puertos de escucha',sort:'Ordenar procesos por',memorySort:'Memoria',nameSort:'Nombre',cpuSort:'Tiempo CPU',baseline:'Línea base',current:'Evidencia actual',upload:'Cargar un snapshot JSON',uploadNote:'Máximo 2 MiB. Se compara en memoria; los datos cargados no se guardan.',compare:'Comparar con el estado actual',selectHistory:'Usar línea base conservada',choose:'Elige una muestra…',noBaseline:'Selecciona una muestra conservada o carga una línea base para comparar.',significant:'Se detectaron cambios significativos',noSignificant:'Sin cambios significativos',metric:'Métrica',delta:'Diferencia',changes:'Cambios de entidades',category:'Categoría',identity:'Identidad',change:'Cambio',details:'Detalles',retained:'Muestras conservadas',boot:'Arranque observado del host',historyNote:'La cronología incluye el arranque observado y las recopilaciones. Los eventos de logs nativos están disponibles mediante el recolector timeline de la CLI.',sampleFindings:'hallazgos',viewSample:'Ver muestra redactada',redactedSample:'Evidencia redactada conservada',cloudUnavailable:'No hay consultas de nube configuradas en esta sesión. Usa los comandos Azure o AWS de la CLI con una identidad de solo lectura.',run:'Ejecutar consulta de solo lectura',cloudNote:'Las consultas usan el proveedor compartido configurado. Aquí no se introducen credenciales ni comandos.',policyUnavailable:'No hay un archivo de políticas configurado. Puedes validar el borrador y evaluarlo con la evidencia actual.',policyNote:'Solo vista previa de políticas. Edita un borrador, valídalo con la evidencia actual y descarga el YAML. No se aplica la política ni se cambia la configuración del host.',policyChanged:'El borrador cambió. Vuelve a validar para actualizar los hallazgos.',policyDraft:'Borrador de política YAML',previewPolicy:'Validar y evaluar',downloadPolicy:'Descargar YAML validado',policyValid:'Política validada',policyInvalid:'Error de validación de política',configuredPolicy:'Vista de política configurada',observedTimeline:'Cronología observada',downloadChecksum:'Descargar checksum del bundle',downloadBundle:'Descargar bundle redactado',downloadJson:'Descargar JSON redactado',downloadReport:'Descargar informe HTML',downloadPdf:'Descargar PDF',downloadSarif:'Exportar hallazgos en SARIF',printReport:'Imprimir / guardar como PDF',reportNote:'Las exportaciones usan la redacción compartida. El bundle incluye su manifiesto; descarga su checksum después del ZIP. La acción Imprimir abre el diálogo del navegador.',settingsNote:'La configuración es de solo lectura. Los tokens se guardan en memoria y nunca en el historial.',setting:'Configuración',value:'Valor',noToken:'Abre la URL de inicio completa que imprime opscope serve para iniciar una sesión local. Si recargas, vuelve a usar esa URL.',error:'No se pudo completar la consulta local.',busy:'La solicitud local está ocupada o limitada. Vuelve a intentarlo en unos segundos.',collected:'Recopilado',searchEmpty:'No hay evidencia coincidente.',maxFile:'Selecciona un archivo JSON de menos de 2 MiB.',invalidFile:'El snapshot cargado no es válido o supera los límites admitidos.',live:'Evidencia en vivo',duration:'Duración de recopilación',available:'disponible',unknown:'Desconocido',days:'días',changed:'cambiado',comparisonReady:'Línea base cargada. Compárala con la evidencia actual.',refreshError:'Actualizaciones en pausa; reconectando…'}
};
Object.assign(words.en, {
analysis:'Saved evidence lab', analysisDescription:'Inspect and analyze a saved snapshot in this local session.',
analysisNote:'Upload a complete Opscope snapshot. Analysis runs on this loopback session, stays out of live history, and always returns redacted evidence.',
analysisUpload:'Open saved snapshot', analysisEmpty:'Start with a saved snapshot JSON. Live collection and saved evidence remain separate.',
analysisLimits:'Snapshot and optional baseline: up to 2 MiB each; every request: 2 MiB total. Indicator text: up to 128 KiB.',
analysisReady:'Saved snapshot validated', analysisLoading:'Validating saved evidence…', analysisRunning:'Running saved evidence analysis…',
analysisOperation:'Analysis', inspect:'Inspect evidence', triage:'Guided triage', ioc:'Match indicators', timeline:'Build timeline',
scenario:'Triage scenario', 'high-cpu':'High CPU', 'disk-full':'Disk capacity', 'port-exposed':'Exposed ports',
indicatorFormat:'Indicator format', indicatorText:'Indicator draft', indicatorUpload:'Open indicator file',
indicatorHint:'CSV requires type,value (optional label). STIX accepts a bundle of supported indicator patterns. Matches reflect observable evidence; no match does not establish that a host is safe.',
analysisBaseline:'Optional saved baseline', analysisNoBaseline:'No baseline selected. Timeline uses the selected snapshot only.',
analysisBaselineReady:'Baseline validated', analysisTimelineNote:'Timeline shows snapshot observations and optional baseline changes. It does not collect native logs.',
analysisRun:'Run analysis', analysisClear:'Clear saved evidence', analysisChanged:'Inputs changed. Run analysis to refresh the result.',
analysisDownload:'Download redacted result JSON', analysisExport:'Export saved snapshot', exportFormat:'Snapshot export format',
savedSource:'Saved snapshot', liveSource:'Live host', retainedSource:'Retained evidence', fleetSource:'Uploaded fleet', cloudSource:'Configured cloud query', alwaysRedacted:'Always redacted', sourceEmpty:'No snapshot selected',
analysisResult:'Analysis result', analysisSnapshot:'Saved snapshot evidence', analysisResultNote:'Result source: the selected saved snapshot. Live host updates do not change this result.',
indicators:'Indicators', observables:'Observed values', matches:'Matches', indicator:'Indicator', guidance:'Next observation',
analysisRequestLimit:'This request exceeds 2 MiB. Use a smaller snapshot, baseline, or indicator list.',
indicatorLimit:'Choose an indicator file or draft up to 128 KiB.', analysisSelect:'Open and validate a saved snapshot first.',
bytes:'bytes', previous:'Previous', next:'Next', rows:'records', page:'Page', of:'of', retryIn:'Retry in', seconds:'seconds',
cloudLoading:'Running configured cloud query…', cloudFailed:'Cloud query did not complete.', cloudEmpty:'Choose a configured query to inspect its evidence.', analysisBaselineRemoved:'Remove baseline', resultOutdated:'Result is out of date.', loading:'Working…'
});
Object.assign(words.es, {
analysis:'Laboratorio de evidencia', analysisDescription:'Inspecciona y analiza un snapshot guardado en esta sesión local.',
analysisNote:'Carga un snapshot completo de Opscope. El análisis usa esta sesión loopback, queda fuera del historial en vivo y siempre devuelve evidencia redactada.',
analysisUpload:'Abrir snapshot guardado', analysisEmpty:'Empieza con un snapshot JSON guardado. La recopilación en vivo y la evidencia guardada están separadas.',
analysisLimits:'Snapshot y línea base opcional: hasta 2 MiB cada uno; cada solicitud: 2 MiB en total. Indicadores: hasta 128 KiB.',
analysisReady:'Snapshot guardado validado', analysisLoading:'Validando evidencia guardada…', analysisRunning:'Analizando evidencia guardada…',
analysisOperation:'Análisis', inspect:'Inspeccionar evidencia', triage:'Triaje guiado', ioc:'Buscar indicadores', timeline:'Crear cronología',
scenario:'Escenario de triaje', 'high-cpu':'CPU alta', 'disk-full':'Capacidad del disco', 'port-exposed':'Puertos expuestos',
indicatorFormat:'Formato de indicadores', indicatorText:'Borrador de indicadores', indicatorUpload:'Abrir archivo de indicadores',
indicatorHint:'CSV requiere type,value (label opcional). STIX admite un bundle de patrones compatibles. Las coincidencias reflejan evidencia observable; su ausencia no demuestra que un host sea seguro.',
analysisBaseline:'Línea base guardada opcional', analysisNoBaseline:'Sin línea base. La cronología usa solo el snapshot seleccionado.',
analysisBaselineReady:'Línea base validada', analysisTimelineNote:'La cronología muestra observaciones del snapshot y cambios de una línea base opcional. No recopila logs nativos.',
analysisRun:'Ejecutar análisis', analysisClear:'Borrar evidencia guardada', analysisChanged:'Las entradas cambiaron. Ejecuta el análisis para actualizar el resultado.',
analysisDownload:'Descargar resultado JSON redactado', analysisExport:'Exportar snapshot guardado', exportFormat:'Formato de exportación',
savedSource:'Snapshot guardado', liveSource:'Host en vivo', retainedSource:'Evidencia conservada', fleetSource:'Flota cargada', cloudSource:'Consulta de nube configurada', alwaysRedacted:'Siempre redactado', sourceEmpty:'Sin snapshot seleccionado',
analysisResult:'Resultado del análisis', analysisSnapshot:'Evidencia del snapshot guardado', analysisResultNote:'Origen del resultado: el snapshot guardado seleccionado. Las actualizaciones del host no cambian este resultado.',
indicators:'Indicadores', observables:'Valores observados', matches:'Coincidencias', indicator:'Indicador', guidance:'Próxima observación',
analysisRequestLimit:'La solicitud supera 2 MiB. Usa un snapshot, línea base o lista de indicadores más pequeños.',
indicatorLimit:'El archivo o borrador de indicadores debe ser de hasta 128 KiB.', analysisSelect:'Abre y valida primero un snapshot guardado.',
bytes:'bytes', previous:'Anterior', next:'Siguiente', rows:'registros', page:'Página', of:'de', retryIn:'Reintentar en', seconds:'segundos',
cloudLoading:'Ejecutando consulta de nube configurada…', cloudFailed:'La consulta de nube no se completó.', cloudEmpty:'Elige una consulta configurada para inspeccionar su evidencia.', analysisBaselineRemoved:'Quitar línea base', resultOutdated:'El resultado está desactualizado.', loading:'Procesando…'
});

Object.assign(words.en, {
menu:'Sections', monitoringGroup:'Monitoring', hostGroup:'Host', investigationGroup:'Investigation', cloudGroup:'Cloud workspace', outputGroup:'Output', systemGroup:'System',
metricsGap:'Metric samples were missed. Reloading retained samples; unavailable observations remain gaps.', cloudMetrics:'Provider metric series', unit:'Unit', aggregation:'Aggregation', samplingPeriod:'Provider sample interval', providerLag:'Observation age', cloudMetricsNote:'Provider timestamps, units and aggregation are shown per series. These observations are separate from the host sampler.', sampleAge:'Evidence age', ago:'ago', stale:'Stale evidence', recovering:'Recovering connection', showLatest:'Show latest evidence', pendingEvidence:'A newer sample is available. Your current controls remain unchanged.',
observedOnly:'observed only; incomplete coverage', rateLimited:'Rate limited', noDataCoverage:'No data', cloudNeedSamples:'A metric plot needs at least two valid provider observations.', complete:'Complete', partial:'Partial coverage', unsupported:'Unsupported', notConfigured:'Not configured', denied:'Permission denied', failed:'Failed', 'timed-out':'Timed out', configured:'Configured', notRequested:'Not requested',
provider:'Provider', scope:'Configured scope', operation:'Operation', allProviders:'All providers', allScopes:'All configured scopes', cloudCatalog:'Provider catalog', cloudCoverage:'Operation coverage', cloudUnavailable:'No cloud queries are configured for this session. Configure a read-only provider and allowlisted scope when starting the CLI server.', cloudCatalogNote:'Providers appear even when no scope is configured. Only explicitly configured read-only actions can run. An unavailable query never means zero resources.',
cloudNoScope:'No scope configured for this provider.', cloudResult:'Cloud evidence', resourceCount:'Observed resources', cloudObserved:'Observation time', cloudDenied:'This query lacks the required read permissions.', cloudTimeout:'The provider query timed out. Its inventory is unknown.', cloudFailedCoverage:'The query failed. Coverage and resource counts are unknown.', cloudEmptyCoverage:'No resources observed in this successful query. Review warnings and service coverage.',
findingsCount:'Matching findings', filterCode:'Finding code', filterSource:'Finding source', allCodes:'All codes', allSources:'All sources', inspectedEvidence:'Finding evidence', copyEvidence:'Copy redacted evidence', copied:'Copied redacted evidence', copyFailed:'Clipboard unavailable; select the displayed redacted text.',
pageSize:'Rows per page', sortAscending:'Sort ascending', sortDescending:'Sort descending', tableExport:'Export redacted table CSV', servicesEmpty:'No service evidence was collected. Service health is unknown.', serviceState:'Service state', allStates:'All states', running:'Running', stopped:'Stopped', unknownState:'Unknown', cpuTimeNote:'CPU time is cumulative process time, not instantaneous CPU utilization.',
columns:'Columns', showCommand:'Show command line', observation:'Observation', fullTableExport:'Switch off full identifiers before exporting this table.',
historyRange:'Retained history range', allHistory:'All retained history', last15m:'Last 15 minutes', last1h:'Last hour', last24h:'Last 24 hours', last7d:'Last 7 days', sampleInspector:'Sample inspector', rawJson:'Raw redacted JSON', timestampUtc:'UTC timestamp', evidenceCoverage:'Evidence coverage', noSamplesInRange:'No retained observations in this range.',
fleetCoverageNote:'Medians describe the selected observations (N shown above). Collection times and available evidence can differ between hosts; outliers are observations, not risk rankings.', driftNeutral:'A positive or negative delta does not establish improvement or deterioration. Compare evidence and collection times.',
stepFile:'Open file', stepValidate:'Validate', stepMode:'Choose analysis', stepRun:'Run', stepResult:'Inspect result', policyLines:'Line numbers', policyDraftState:'Edited / not validated', reportInvestigate:'Inspect and share', reportAutomate:'Automate findings', reportBundle:'Evidence bundle and integrity', checksumNote:'SHA-256 verifies downloaded bytes. It is not a digital signature.',
effectiveSettings:'Effective server configuration', preferences:'Interface preferences', density:'Table density', standardDensity:'Standard', compactDensity:'Compact', comfortableDensity:'Comfortable', copySettings:'Copy safe configuration', settingsCopied:'Safe configuration copied', searchCount:'matching records', showing:'Showing', errorAuth:'This local session is no longer authorized. Reopen its bootstrap URL.', errorUnavailable:'The local service is unavailable. Try again when it is running.', errorInvalid:'The local request was rejected. Check the selected input.', requestTimeout:'The local request timed out.'
});
Object.assign(words.es, {
menu:'Secciones', monitoringGroup:'Supervisión', hostGroup:'Host', investigationGroup:'Investigación', cloudGroup:'Espacio de nube', outputGroup:'Salida', systemGroup:'Sistema',
metricsGap:'Faltan muestras de métricas. Se recuperan las conservadas; las observaciones no disponibles mantienen sus huecos.', cloudMetrics:'Series de métricas del proveedor', unit:'Unidad', aggregation:'Agregación', samplingPeriod:'Intervalo de muestreo del proveedor', providerLag:'Edad de la observación', cloudMetricsNote:'Cada serie indica fechas, unidades y agregación del proveedor. Estas observaciones están separadas del muestreo del host.', sampleAge:'Edad de la evidencia', ago:'atrás', stale:'Evidencia obsoleta', recovering:'Recuperando conexión', showLatest:'Mostrar evidencia reciente', pendingEvidence:'Hay una muestra más reciente. Se conservan tus controles actuales.',
observedOnly:'solo observados; cobertura incompleta', rateLimited:'Límite de consultas', noDataCoverage:'Sin datos', cloudNeedSamples:'La gráfica necesita al menos dos observaciones válidas del proveedor.', complete:'Completa', partial:'Cobertura parcial', unsupported:'No compatible', notConfigured:'Sin configurar', denied:'Permiso denegado', failed:'Error', 'timed-out':'Tiempo agotado', configured:'Configurado', notRequested:'No solicitado',
provider:'Proveedor', scope:'Ámbito configurado', operation:'Operación', allProviders:'Todos los proveedores', allScopes:'Todos los ámbitos configurados', cloudCatalog:'Catálogo de proveedores', cloudCoverage:'Cobertura por operación', cloudUnavailable:'No hay consultas de nube configuradas en esta sesión. Configura un proveedor de solo lectura y ámbitos autorizados al iniciar el servidor CLI.', cloudCatalogNote:'Los proveedores aparecen aunque no tengan ámbitos configurados. Solo se ejecutan acciones de lectura configuradas expresamente. Una consulta no disponible nunca equivale a cero recursos.',
cloudNoScope:'Este proveedor no tiene ámbitos configurados.', cloudResult:'Evidencia de nube', resourceCount:'Recursos observados', cloudObserved:'Hora de observación', cloudDenied:'La consulta no tiene los permisos de lectura necesarios.', cloudTimeout:'La consulta agotó el tiempo de espera. Se desconoce su inventario.', cloudFailedCoverage:'La consulta falló. Se desconocen su cobertura y número de recursos.', cloudEmptyCoverage:'La consulta correcta no observó recursos. Revisa los avisos y la cobertura por servicio.',
findingsCount:'Hallazgos coincidentes', filterCode:'Código del hallazgo', filterSource:'Origen del hallazgo', allCodes:'Todos los códigos', allSources:'Todos los orígenes', inspectedEvidence:'Evidencia del hallazgo', copyEvidence:'Copiar evidencia redactada', copied:'Evidencia redactada copiada', copyFailed:'Portapapeles no disponible; selecciona el texto redactado mostrado.',
pageSize:'Filas por página', sortAscending:'Orden ascendente', sortDescending:'Orden descendente', tableExport:'Exportar tabla redactada CSV', servicesEmpty:'No se recopiló evidencia de servicios. Se desconoce su estado.', serviceState:'Estado del servicio', allStates:'Todos los estados', running:'En ejecución', stopped:'Detenido', unknownState:'Desconocido', cpuTimeNote:'El tiempo CPU es acumulado del proceso; no es su uso instantáneo de CPU.',
columns:'Columnas', showCommand:'Mostrar línea de comandos', observation:'Observación', fullTableExport:'Desactiva los identificadores completos antes de exportar la tabla.',
historyRange:'Ventana del historial conservado', allHistory:'Todo el historial conservado', last15m:'Últimos 15 minutos', last1h:'Última hora', last24h:'Últimas 24 horas', last7d:'Últimos 7 días', sampleInspector:'Inspector de muestra', rawJson:'JSON redactado original', timestampUtc:'Fecha y hora UTC', evidenceCoverage:'Cobertura de evidencia', noSamplesInRange:'No hay observaciones conservadas en esta ventana.',
fleetCoverageNote:'Las medianas describen las observaciones seleccionadas (N indicado arriba). Las fechas y la evidencia disponible pueden variar entre hosts; los valores atípicos son observaciones, no clasificaciones de riesgo.', driftNeutral:'Una diferencia positiva o negativa no demuestra mejora ni deterioro. Compara la evidencia y las fechas de recopilación.',
stepFile:'Abrir archivo', stepValidate:'Validar', stepMode:'Elegir análisis', stepRun:'Ejecutar', stepResult:'Inspeccionar resultado', policyLines:'Números de línea', policyDraftState:'Editado / sin validar', reportInvestigate:'Inspeccionar y compartir', reportAutomate:'Automatizar hallazgos', reportBundle:'Bundle de evidencia e integridad', checksumNote:'SHA-256 verifica los bytes descargados. No es una firma digital.',
effectiveSettings:'Configuración efectiva del servidor', preferences:'Preferencias de interfaz', density:'Densidad de tablas', standardDensity:'Estándar', compactDensity:'Compacta', comfortableDensity:'Amplia', copySettings:'Copiar configuración segura', settingsCopied:'Configuración segura copiada', searchCount:'registros coincidentes', showing:'Mostrando', errorAuth:'La sesión local ya no está autorizada. Abre de nuevo su URL de inicio.', errorUnavailable:'El servicio local no está disponible. Reintenta cuando esté activo.', errorInvalid:'Se rechazó la solicitud local. Revisa los datos seleccionados.', requestTimeout:'La solicitud local agotó el tiempo de espera.'
});

const requestLimit = 2 * 1024 * 1024, indicatorLimit = 128 * 1024;
const utf8Length = value => new TextEncoder().encode(value).byteLength;
let analysisSnapshot = null, analysisSafe = null, analysisBaseline = null, analysisBaselineSafe = null;
let analysisOperation = 'inspect', analysisScenario = 'high-cpu', analysisIndicatorFormat = 'csv', analysisIndicatorText = '';
let analysisReport = null, analysisError = null, analysisBusy = false, analysisVersion = 0, analysisController = null;
let cloudAction = null, cloudBusy = false, cloudError = null, cloudVersion = 0;
let analysisExportFormat = 'json', policyBusy = false, collectionBusy = false, cooldownUntil = 0, snapshotVersion = 0;
const tablePages = new Map(), tableSizes = new Map(), tableSorts = new Map();
const knownProviders = new Set(['azure','aws','gcp','oci','digitalocean','hetzner','cloudflare','openstack','alibaba','ibm','scaleway']);
const knownOperations = new Set(['inventory','health','posture','metrics','cost','patches']);
const knownViews = new Set(['overview','findings','processes','services','analysis','drift','fleet','history','cloud','policy','reports','settings']);
let cloudCatalog = null, cloudProvider = 'all', cloudScope = 'all', findingCode = 'all', findingSource = 'all', serviceFilter = 'all', historyRange = 'all';
let pendingEvidence = false, connectionState = 'connecting', streamController = null, lastTransportAt = 0, streamFailures = 0, chartHandle = null, chartNode = null, chartContext = null, lastMetricSequence = 0;
const cloudPlotRenderers = new Set();
let density = 'standard', showCommand = true, metricRecovery = null;

let lastBundleChecksum = null, fleetSnapshots = [], fleetReport = null, fleetError = null, fleetBusy = false;
let driftBusy = false, driftVersion = 0;
let privacyVersion = 0, safeSnapshot = null, timelineReport = null, policyPreview = null, policyError = null, policyValidatedText = null;
let policyYaml = 'version: 1\nthresholds:\n  cpuWarningPercent: 85\n  cpuCriticalPercent: 95\n  memoryWarningPercent: 85\n  memoryCriticalPercent: 95\n  diskWarningPercent: 85\n  diskCriticalPercent: 95\nrequiredServices: []\nrules: []\n';
let lang = 'en', view = 'overview', snapshot = null, entries = [], settings = null, capabilities = {cloud:[],policy:false}, baseline = null, diff = null, selectedSample = null, severity = 'all', sort = 'memorySort', cloudResult = null, policyResult = null, disposed = false;
try {
    lang = localStorage.getItem('opscope-language') || 'en';
    const theme = localStorage.getItem('opscope-theme'); document.documentElement.dataset.theme = theme === 'light' ? 'light' : 'dark';
    const savedDensity = localStorage.getItem('opscope-density'); density = ['standard','compact','comfortable'].includes(savedDensity) ? savedDensity : 'standard';
    showCommand = localStorage.getItem('opscope-process-command') !== 'hidden';
} catch {}
document.documentElement.dataset.density = density;
history.replaceState({view:'overview'}, '', location.pathname);
if(!words[lang])lang='en';
const t = key => words[lang][key] || key;
const el = (tag, text, cls) => {const node=document.createElement(tag);if(text!==undefined&&text!==null)node.textContent=String(text);if(cls)node.className=cls;return node;};
const append = (parent,...children)=>{children.flat().forEach(child=>{if(child)parent.append(child);});return parent;};
const button = (text, callback, cls) => {const node=el('button',text,cls);node.type='button';node.addEventListener('click',callback);return node;};
const date = value => Number.isFinite(Date.parse(value)) ? new Date(value).toLocaleString(lang==='es'?'es-ES':'en-GB',{year:'numeric',month:'short',day:'numeric',hour:'2-digit',minute:'2-digit',second:'2-digit',timeZoneName:'short'}) : t('unknown');
const number = value => value !== null && value !== undefined && value !== '' && Number.isFinite(Number(value)) ? Number(value).toLocaleString(lang==='es'?'es-ES':'en-GB',{maximumFractionDigits:1}) : '—';
const severityName = value => ['info','warning','critical'][typeof value==='number'?value:['info','warning','critical'].indexOf(String(value).toLowerCase())]||'info';
const match = value => !String($('search').value).trim() || JSON.stringify(value).toLowerCase().includes($('search').value.trim().toLowerCase());
function notice(message){$('notice').textContent=message;$('notice').hidden=!message;}
function translate(){document.documentElement.lang=lang;$('language').value=lang;document.querySelectorAll('[data-i18n]').forEach(node=>node.textContent=t(node.dataset.i18n));document.querySelectorAll('[data-placeholder]').forEach(node=>node.placeholder=t(node.dataset.placeholder));$('privacy').textContent=t($('full').checked?'fullWarning':'redacted');setConnection(connectionState);$('page-title').textContent=t(view);$('navigation').setAttribute('aria-label',t('workspace'));$('theme').setAttribute('aria-label',lang==='es'?'Cambiar tema de color':'Switch color theme');render();}
async function api(path, options = {}) {
    // EN: Authenticate local requests and expose bounded failure details without automatic write retries.
    // ES: Se autentican las peticiones locales y se muestran errores acotados sin reintentar escrituras automáticamente.
    const controller=path==='/api/events'?null:new AbortController(), forwardAbort=()=>controller?.abort(options.signal?.reason);
    if(options.signal?.aborted)forwardAbort(); else options.signal?.addEventListener('abort',forwardAbort,{once:true});
    let timedOut=false, response;
    const timeout=controller?setTimeout(()=>{timedOut=true;controller.abort();},path.startsWith('/api/cloud/')?65000:30000):null;
    try {
        response=await fetch(path,{...options,signal:controller?.signal || options.signal,headers:{'X-Opscope-Token':token || '',...options.headers},credentials:'omit',cache:'no-store',referrerPolicy:'no-referrer'});
    } catch(error) {
        if(options.signal?.aborted)throw error;
        throw new Error(t(timedOut?'requestTimeout':'errorUnavailable'));
    } finally {clearTimeout(timeout);options.signal?.removeEventListener('abort',forwardAbort);}
    if (response.ok) return response;
    let message = response.status === 429 ? t('busy') : response.status === 401 || response.status === 403 ? t('errorAuth') : response.status === 400 || response.status === 413 ? t('errorInvalid') : response.status === 504 ? t('requestTimeout') : response.status >= 500 ? t('errorUnavailable') : t('error'), failureReport = null;
    if (response.status === 401 || response.status === 403) setConnection('disconnected');
    if (response.status === 429) {
        const retry = response.headers.get('Retry-After');
        const delay = /^\d+$/.test(retry || '') ? Number(retry) : Math.ceil((Date.parse(retry) - Date.now()) / 1000);
        const seconds = Number.isFinite(delay) && delay > 0 ? Math.min(delay, 3600) : 2;
        cooldownUntil = Math.max(cooldownUntil, Date.now() + seconds * 1000);
        message = `${t('busy')} ${t('retryIn')} ${seconds} ${t('seconds')}.`;
        updateCollectionControl();
    } else if (['/api/policy/preview', '/api/fleet', '/api/analyze', '/api/report'].includes(path) || path.startsWith('/api/cloud/')) {
        try {
            const problem = await response.json();
            if (typeof problem.kind === 'string' && Array.isArray(problem.findings) && Array.isArray(problem.warnings)) failureReport = problem;
            message = [problem.error, problem.detail].filter(value => typeof value === 'string').join(' ') || message;
        } catch {}
    }
    const error = new Error(message);
    error.status = response.status;
    error.report = failureReport;
    throw error;
}
function updateCollectionControl() {
    const control = $('collect'), remaining = Math.max(0, Math.ceil((cooldownUntil - Date.now()) / 1000));
    control.disabled = !token || collectionBusy || remaining > 0;
    control.querySelector('[data-i18n]').textContent = collectionBusy ? t('collecting') : remaining ? `${t('retryIn')} ${remaining}s` : t('collect');
    control.title = remaining ? `${t('retryIn')} ${remaining} ${t('seconds')}` : '';
}
setInterval(updateCollectionControl, 1000);

async function json(path,options){return (await api(path,options)).json();}
function setNavigationOpen(open, returnFocus = false) {
    document.body.classList.toggle('navigation-open', open);
    $('navigation-toggle').setAttribute('aria-expanded', String(open));
    if (returnFocus) $('navigation-toggle').focus();
}
function navigate(next, record = true) {
    if (!knownViews.has(next)) return;
    const changed = next !== view;
    view = next;
    if (changed && record) history.pushState({view}, '', location.pathname);
    document.querySelectorAll('.nav-item').forEach(item => {
        const active = item.dataset.view === view; item.classList.toggle('active',active);
        if (active) item.setAttribute('aria-current','page'); else item.removeAttribute('aria-current');
    });
    if (['analysis','history','fleet','cloud'].includes(view) && $('full').checked) {
        privacyVersion++; snapshotVersion++; $('full').checked = false; snapshot = safeSnapshot;
    }
    setNavigationOpen(false);
    $('page-title').textContent = t(view);
    pendingEvidence = false;
    render();
    if (matchMedia('(max-width:789px)').matches) $('content').focus();
}
function setConnection(status) {
    connectionState = status;
    const label = status === 'connected' ? 'connected' : status === 'recovering' ? 'recovering' : status === 'disconnected' ? 'disconnected' : 'connecting';
    const node = $('connection'); if (node.textContent !== t(label)) node.textContent = t(label);
    node.dataset.state = status;
    window.OpscopeCharts?.setConnection(status);
    updateFreshness();
}
function updateFreshness() {
    const stamp = snapshot?.collectedAtUtc, age = Number.isFinite(Date.parse(stamp)) ? Math.max(0,Math.floor((Date.now()-Date.parse(stamp))/1000)) : null;
    const stale = age !== null && age > Math.max(60,Number(settings?.refreshSeconds || 30)*3);
    const saved = ['analysis','history','fleet','cloud'].includes(view);
    const node = $('sample-age');
    node.textContent = saved ? t('alwaysRedacted') : age === null ? t('noData') : `${stale ? t('stale') : t('sampleAge')}: ${age < 60 ? age+' s' : Math.floor(age/60)+' min'} · ${date(stamp)}`;
    node.parentElement.dataset.state = stale && !saved ? 'stale' : connectionState;
    $('show-latest').hidden = !pendingEvidence || saved;
    $('show-latest').title = t('pendingEvidence');
}
setInterval(updateFreshness, 1000);
function panel(title){const node=el('section',null,'panel');node.append(el('h2',title));return node;}
function empty(parent,message='noData'){parent.append(el('p',t(message),'empty'));}
function paginate(items, renderItems, key) {
    // EN: Mount only one page of rows so large evidence sets do not flood the DOM.
    // ES: Solo se monta una página de filas para que grandes conjuntos de evidencia no saturen el DOM.
    const wrap = el('div'), size = tableSizes.get(key) || 50, total = Math.max(1, Math.ceil(items.length / size));
    let page = Math.min(tablePages.get(key) || 0, total - 1);
    const body = el('div'), controls = el('div', null, 'pagination');
    const status = el('span', null, 'muted');
    status.setAttribute('role', 'status');
    status.setAttribute('aria-live', 'polite');
    const previous = button(t('previous'), () => changePage(page - 1));
    const next = button(t('next'), () => changePage(page + 1));
    function changePage(value) {
        page = value;
        tablePages.set(key, page);
        draw();
        const focus = value === 0 ? next : previous;
        focus.focus();
    }
    function draw() {
        body.replaceChildren(renderItems(items.slice(page * size, (page + 1) * size)));
        previous.disabled = page === 0;
        next.disabled = page === total - 1;
        status.textContent = `${items.length} ${t('rows')} · ${t('page')} ${page + 1} ${t('of')} ${total}`;
    }
    append(controls, status, previous, next);
    append(wrap, body, controls);
    controls.hidden = items.length <= size;
    draw();
    return wrap;
}
function csvValue(value) {
    const text = value instanceof Node ? value.textContent : value === null || value === undefined ? '' : String(value);
    return '"' + (/^(?:[\s\uFEFF]*[=+\-@]|[\t\r\n])/.test(text) ? "'" : '') + text.replaceAll('"','""') + '"';
}
function table(headers, rows, key = `${view}:${headers.join(':')}`) {
    if (!rows.length) return el('p', t('noRows'), 'empty');
    const root = el('div'), controls = el('div', null, 'table-toolbar');
    const count = el('span', `${rows.length} ${t('rows')}`, 'table-count'), label = el('label', t('pageSize')), size = el('select');
    size.setAttribute('aria-label',t('pageSize')); [25,50,100].forEach(value => { const option = el('option',value); option.value = value; size.append(option); });
    size.value = tableSizes.get(key) || 50;
    const content = el('div');
    size.addEventListener('change',() => { tableSizes.set(key,Number(size.value)); tablePages.set(key,0); draw(); });
    label.append(size);
    const exportButton = button(t('tableExport'),() => {
        if ($('full').checked && !['analysis','history','fleet','cloud'].includes(view)) { notice(t('fullTableExport')); return; }
        const csv = [headers.map(t),...sortedRows()].map(row => row.map(csvValue).join(',')).join('\r\n');
        saveBlob(new Blob(['\uFEFF'+csv],{type:'text/csv;charset=utf-8'}),`opscope-${view}-redacted.csv`);
    });
    exportButton.disabled = $('full').checked && !['analysis','history','fleet','cloud'].includes(view);
    append(controls,count,label,exportButton); append(root,controls,content);
    function sortedRows() {
        const order = tableSorts.get(key); if (!order) return rows;
        return [...rows].sort((a,b) => {
            const left = a[order.column] instanceof Node ? a[order.column].textContent : a[order.column];
            const right = b[order.column] instanceof Node ? b[order.column].textContent : b[order.column];
            const result = typeof left === 'number' && typeof right === 'number' ? left-right : String(left ?? '').localeCompare(String(right ?? ''),lang,{numeric:true,sensitivity:'base'});
            return order.descending ? -result : result;
        });
    }
    function draw() {
        const focused = document.activeElement, column = focused?.dataset.sortColumn;
        content.replaceChildren(paginate(sortedRows(), pageRows => {
            const wrap = el('div', null, 'table-wrap'), node = el('table'), head = el('thead'), headrow = el('tr');
            wrap.tabIndex = 0; wrap.setAttribute('role','region'); wrap.setAttribute('aria-label',headers.map(t).join(' / '));
            headers.forEach((label,index) => {
                const th = el('th'), current = tableSorts.get(key), sortButton = button(t(label),() => {
                    tableSorts.set(key,{column:index,descending:current?.column === index ? !current.descending : false}); tablePages.set(key,0); draw();
                },'table-sort');
                sortButton.dataset.sortColumn = index;
                sortButton.title = t(current?.column === index && !current.descending ? 'sortDescending' : 'sortAscending');
                th.scope = 'col';
                if (current?.column === index) { th.setAttribute('aria-sort',current.descending ? 'descending' : 'ascending'); sortButton.append(el('span',current.descending ? ' ↓' : ' ↑')); }
                th.append(sortButton); headrow.append(th);
            });
            head.append(headrow); const body = el('tbody');
            pageRows.forEach(row => { const tr = el('tr'); row.forEach(value => { const td = el('td'); if (value instanceof Node) td.append(value); else td.textContent = value === null || value === undefined || value === '' ? '—' : String(value); tr.append(td); }); body.append(tr); });
            append(node,head,body); wrap.append(node); return wrap;
        },key));
        if (column !== undefined) content.querySelector(`[data-sort-column="${column}"]`)?.focus();
    }
    draw(); return root;
}

function facts(pairs){const list=el('dl',null,'facts');pairs.forEach(([key,value])=>{const item=el('div');append(item,el('dt',t(key)),el('dd',value));list.append(item);});return list;}
function findingsList(findings, key = `${view}:findings`) {
    if (!findings.length) { const emptyList = el('div'); empty(emptyList, 'noFindings'); return emptyList; }
    const sorted = [...findings].sort((a,b) => ['info','warning','critical'].indexOf(severityName(b.severity)) - ['info','warning','critical'].indexOf(severityName(a.severity)) || String(a.code).localeCompare(String(b.code)));
    return paginate(sorted, pageFindings => {
        const list = el('div');
        pageFindings.forEach(finding => {
            const item = el('article', null, 'finding'), level = severityName(finding.severity), body = el('div');
            append(body, el('div', `${t(level).toUpperCase()} · ${finding.code}`, 'finding-meta'), el('h3', finding.title), el('p', finding.detail), el('p', `${t('recommendation')}: ${finding.recommendation}`, 'recommendation'));
            const detail = el('details',null,'finding-details');
            const observed = view === 'analysis' ? analysisSafe?.collectedAtUtc : view === 'cloud' ? cloudResult?.collectedAtUtc : snapshot?.collectedAtUtc;
            append(detail,el('summary',t('inspectedEvidence')), facts([['code',finding.code],['source',finding.source || finding.ruleId || t('sample')],['observation',date(observed)]]));
            if (finding.evidence !== undefined) detail.append(el('pre', typeof finding.evidence === 'string' ? finding.evidence : JSON.stringify(finding.evidence,null,2)));
            const copy = button(t('copyEvidence'),async() => {
                if ($('full').checked && !['analysis','history','fleet','cloud'].includes(view)) return;
                try { await navigator.clipboard.writeText(JSON.stringify(finding,null,2)); notice(t('copied')); } catch { notice(t('copyFailed')); }
            });
            copy.disabled = $('full').checked && !['analysis','history','fleet','cloud'].includes(view);
            detail.append(copy); body.append(detail);
            append(item, el('span', null, `severity-dot ${level}`), body); list.append(item);
        });
        return list;
    }, key);
}

function chart() {
    const wrap=panel(t('trend')), context=`${view}:${lang}`;
    wrap.append(el('p',t(view==='history'?'trendNote':'live'),'muted'));
    if(chartNode && chartContext===context){wrap.append(chartNode);return wrap;}
    chartHandle?.dispose();chartHandle=null;chartNode=el('div',null,'ops-chart');chartNode.id='resource-chart';chartContext=context;wrap.append(chartNode);
    if(window.OpscopeCharts){
        [...entries].sort((a,b)=>Date.parse(a.collectedAtUtc)-Date.parse(b.collectedAtUtc)).forEach(sample=>window.OpscopeCharts.push(sample));
        chartHandle=window.OpscopeCharts.mount(chartNode,{language:lang,source:view==='history'?'snapshots':undefined});
    }else empty(chartNode,'needHistory');return wrap;
}

function overview(){const s=snapshot,cards=el('div',null,'cards'),disks=s.disks.filter(d=>d.isReady),highest=disks.length?Math.max(...disks.map(d=>d.usedPercent)):null;[['cpu',s.cpuUsedPercent,'%','sample'],['memory',s.memory.usedPercent,'%','sample'],['disk',highest,'%',`${disks.length} ${t('diskCount')}`],['listeners',s.listeners.length,'',`${s.security.exposedListeners} ${t('exposed')}`]].forEach(([label,value,unit,description])=>{const card=el('article',null,'card'+(value>85?' warning':''));append(card,el('div',t(label),'card-label'),el('p',`${value===null?'—':number(value)}${value===null?'':unit}`,'card-value'));if(unit&&value!==null){const progress=el('progress');progress.max=100;progress.value=Math.max(0,Math.min(100,value));progress.setAttribute('aria-label',`${t(label)} ${number(value)}%`);card.append(progress);}card.append(el('div',words[lang][description]||description,'card-description'));cards.append(card);});$('view').append(cards);const split=el('div',null,'grid-two'),priority=panel(t('priority'));priority.append(findingsList(s.findings.slice().sort((a,b)=>Number(b.severity)-Number(a.severity)).slice(0,3)));if(s.findings.length)priority.append(button(t('allFindings'),()=>navigate('findings')));const host=panel(t('host'));host.append(facts([['host',s.host.hostname],['os',s.host.osDescription],['platform',`${s.host.platform} · ${s.host.architecture}`],['uptime',s.host.uptime],['privilege',t(s.host.isElevated?'elevated':'standard')],['processors',s.host.processorCount],['firewall',t(s.security.protectionVerified?'verified':'unverified')],['duration',`${number(parseDuration(s.collectionDuration))} s`]]));append(split,priority,host);$('view').append(split,chart());const warnings=panel(t('warnings'));if(!s.collectionWarnings.length)warnings.append(el('p',t('noWarnings'),'muted'));else{const list=el('ul');s.collectionWarnings.forEach(item=>list.append(el('li',item)));warnings.append(list);}$('view').append(warnings);}
function parseDuration(value){const parts=String(value||'0').split(':');return parts.reduce((sum,part)=>sum*60+Number(part),0);}
function optionFilter(id,label,values,value,onChange,allLabel = 'all') {
    const group = el('div',null,'field'), caption = el('label',t(label)), select = el('select');
    select.id = id; caption.htmlFor = id;
    [[ 'all',t(allLabel) ],...values].forEach(([key,text]) => { const option = el('option',text); option.value = key; select.append(option); });
    select.value = value; select.addEventListener('change',() => onChange(select.value)); append(group,caption,select); return group;
}
function showFindings() {
    const wrap = panel(t('findings')), controls = el('div',null,'control-row');
    controls.append(optionFilter('severity-filter','severity',['critical','warning','info'].map(key=>[key,t(key)]),severity,value=>{severity=value;tablePages.clear();render();}));
    const codes = [...new Set(snapshot.findings.map(item=>item.code))].filter(Boolean).sort();
    const sources = [...new Set(snapshot.findings.map(item=>item.source || item.ruleId || t('sample')))].sort();
    controls.append(optionFilter('finding-code','filterCode',codes.map(key=>[key,key]),findingCode,value=>{findingCode=value;tablePages.clear();render();},'allCodes'));
    controls.append(optionFilter('finding-source','filterSource',sources.map(key=>[key,key]),findingSource,value=>{findingSource=value;tablePages.clear();render();},'allSources'));
    const filtered = snapshot.findings.filter(item => match(item) && (severity === 'all' || severityName(item.severity) === severity) && (findingCode === 'all' || item.code === findingCode) && (findingSource === 'all' || (item.source || item.ruleId || t('sample')) === findingSource));
    const counts = el('div',null,'status-counts');
    ['critical','warning','info'].forEach(level=>counts.append(el('span',`${t(level)}: ${snapshot.findings.filter(item=>severityName(item.severity)===level).length}`,'tag')));
    append(wrap,counts,controls,el('p',`${t('findingsCount')}: ${filtered.length}`,'muted'),findingsList(filtered)); $('view').append(wrap);
}
function showProcesses() {
    const wrap = panel(t('processList')), controls = el('div',null,'control-row'), label = el('label',t('sort')), select = el('select');
    select.id = 'process-sort'; label.htmlFor = select.id;
    ['memorySort','cpuSort','nameSort'].forEach(key=>{const option=el('option',t(key));option.value=key;select.append(option);});
    select.value=sort; select.addEventListener('change',()=>{sort=select.value;tablePages.clear();render();});
    const commandLabel = el('label'), commandToggle = el('input'); commandToggle.type='checkbox'; commandToggle.id='process-command'; commandToggle.checked=showCommand;
    commandToggle.addEventListener('change',()=>{showCommand=commandToggle.checked;try{localStorage.setItem('opscope-process-command',showCommand?'visible':'hidden');}catch{}render();});
    append(commandLabel,commandToggle,el('span',t('showCommand'))); append(controls,label,select,commandLabel);
    const data=snapshot.processes.filter(match).sort((a,b)=>sort==='nameSort'?a.name.localeCompare(b.name):sort==='cpuSort'?parseDuration(b.cpuTime)-parseDuration(a.cpuTime):b.workingSetBytes-a.workingSetBytes);
    const headers = ['pid','name','user','workingSet','cpuTime']; if(showCommand)headers.push('command');
    const rows = data.map(process=>{const row=[process.id,process.name,process.user,number(process.workingSetMb),process.cpuTime];if(showCommand)row.push(process.commandLine);return row;});
    append(wrap,controls,el('p',t('cpuTimeNote'),'muted workspace-note'),table(headers,rows,'processes:main'));
    const ports=panel(t('portList')); ports.append(table(['protocol','address','process','source'],snapshot.listeners.filter(match).map(port=>[port.protocol,port.localAddress,port.process,port.source])));
    $('view').append(wrap,ports);
}
function normalizedServiceState(value) {
    const state = String(value || '').toLowerCase();
    if (/failed|failure|error/.test(state)) return 'failed';
    if (/running|active/.test(state) && !/inactive/.test(state)) return 'running';
    if (/stopped|inactive|dead/.test(state)) return 'stopped'; return 'unknownState';
}
function showServices() {
    const wrap=panel(t('services')), counts=el('div',null,'status-counts'), controls=el('div',null,'control-row');
    ['running','stopped','failed','unknownState'].forEach(state=>counts.append(el('span',`${t(state)}: ${snapshot.services.filter(service=>normalizedServiceState(service.state)===state).length}`,'tag')));
    controls.append(optionFilter('service-state','serviceState',['running','stopped','failed','unknownState'].map(state=>[state,t(state)]),serviceFilter,value=>{serviceFilter=value;tablePages.clear();render();},'allStates'));
    append(wrap,counts,controls,el('p',`${t('observation')}: ${date(snapshot.collectedAtUtc)}`,'muted workspace-note'));
    if(!snapshot.services.length)empty(wrap,'servicesEmpty');
    else wrap.append(table(['name','state','serviceDescription','source'],snapshot.services.filter(service=>match(service)&&(serviceFilter==='all'||normalizedServiceState(service.state)===serviceFilter)).map(service=>[service.name,service.state || t('unknownState'),service.description,service.source])));
    $('view').append(wrap);
}

function historySelect(callback) {
    const select = el('select'), first = el('option', t('choose'));
    select.setAttribute('aria-label', t('selectHistory'));
    first.value = '';
    select.append(first);
    entries.forEach(item => {
        const option = el('option', `${date(item.collectedAtUtc)} · ${item.findingCount} ${t('sampleFindings')}`);
        option.value = item.id;
        select.append(option);
    });
    select.addEventListener('change', () => callback(select.value));
    return select;
}
async function loadDriftBaseline(load) {
    // EN: Clear old evidence before any await; only the latest selection may become ready.
    // ES: Se borra la evidencia anterior antes de esperar; solo la última selección puede quedar lista.
    const version = ++driftVersion;
    baseline = diff = null;
    driftBusy = Boolean(load);
    notice(load ? t('loading') : '');
    render();
    if (!load) return;
    try {
        const next = await load();
        if (version !== driftVersion) return;
        baseline = next;
        notice(t('comparisonReady'));
    } catch (error) {
        if (version === driftVersion) notice(error.message);
    } finally {
        if (version === driftVersion) { driftBusy = false; render(); }
    }
}
async function compareDrift() {
    if (!baseline || driftBusy) return;
    const version = driftVersion, selected = baseline;
    driftBusy = true;
    diff = null;
    notice(t('loading'));
    render();
    try {
        const result = await json('/api/diff', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(selected)});
        if (version !== driftVersion) return;
        diff = result;
        notice('');
    } catch (error) {
        if (version === driftVersion) notice(error.message);
    } finally {
        if (version === driftVersion) { driftBusy = false; render(); }
    }
}
function showDrift() {
    // EN: Readiness lives outside the DOM so live SSE renders cannot enable a pending comparison.
    // ES: El estado vive fuera del DOM para que las actualizaciones SSE no habiliten una comparación pendiente.
    const wrap = panel(t('drift')), controls = el('div', null, 'control-row'), file = el('input');
    file.type = 'file';
    file.accept = '.json,application/json';
    file.id = 'baseline-upload';
    const label = el('label', t('upload'));
    label.htmlFor = file.id;
    file.addEventListener('change', () => {
        const chosen = file.files[0];
        loadDriftBaseline(async () => {
            if (!chosen || chosen.size > 2 * 1024 * 1024) throw new Error(t('maxFile'));
            try {
                const content = await chosen.text(), parsed = JSON.parse(content);
                await json('/api/diff', {method:'POST', headers:{'Content-Type':'application/json'}, body:content});
                return parsed;
            } catch { throw new Error(t('invalidFile')); }
        });
    });
    const retained = historySelect(id => loadDriftBaseline(id ? () => json(`/api/history/${encodeURIComponent(id)}`) : null));
    const compare = button(t('compare'), compareDrift, 'primary');
    compare.disabled = !baseline || driftBusy;
    append(controls, label, file, retained, compare);
    wrap.append(controls, el('p', t('uploadNote'), 'muted'));
    if (!baseline) empty(wrap, 'noBaseline');
    else {
        const split = el('div', null, 'split-evidence');
        [['baseline', baseline], ['current', snapshot]].forEach(([title, evidence]) => {
            const side = el('section');
            append(side, el('h3', t(title)), el('p', date(evidence.collectedAtUtc), 'muted'), facts([
                ['cpu', `${number(evidence.cpuUsedPercent)}%`], ['memory', `${number(evidence.memory.usedPercent)}%`],
                ['listeners', evidence.listeners.length], ['services', evidence.services.length], ['findings', evidence.findings.length]
            ]));
            split.append(side);
        });
        wrap.append(split,el('p',t('driftNeutral'),'muted coverage-note'));
        if (diff) {
            if (diff.warnings?.length) {
                const limitations = el('ul', null, 'warning-text');
                diff.warnings.forEach(warning => limitations.append(el('li', warning)));
                wrap.append(limitations);
            }
            wrap.append(el('h3', t(diff.significant ? 'significant' : 'noSignificant')),
                table(['metric','baseline','current','delta'], diff.metrics.map(metric => [metric.name, `${number(metric.baseline)} ${metric.unit}`, `${number(metric.current)} ${metric.unit}`, `${metric.delta > 0 ? '+' : ''}${number(metric.delta)} ${metric.unit}`])),
                el('h3', t('changes')), table(['category','identity','change','details'], diff.changes.map(change => [change.category, change.identity, change.change, change.details])));
        }
    }
    $('view').append(wrap);
}
function showFleet(){const wrap=panel(t('fleet'));append(wrap,el('p',t('fleetLocal'),'muted'),el('p',t('fleetLimit'),'muted'));const controls=el('div',null,'control-row'),label=el('label',t('fleetUpload')),upload=el('input');upload.type='file';upload.multiple=true;upload.accept='.json,application/json';upload.id='fleet-upload';label.htmlFor=upload.id;upload.disabled=fleetBusy;upload.addEventListener('change',async()=>{const files=[...upload.files];fleetReport=null;fleetError=null;fleetSnapshots=[];if(files.length<2||files.length>100||files.reduce((total,file)=>total+file.size,0)>2*1024*1024){fleetError=t('fleetLimit');render();return;}try{const snapshots=[];for(const file of files)snapshots.push(JSON.parse(await file.text()));const body=JSON.stringify({snapshots});if(new TextEncoder().encode(body).byteLength>2*1024*1024)throw new Error();fleetSnapshots=snapshots;}catch{fleetError=t('fleetInvalid');}render();});const compare=button(t('fleetCompare'),async()=>{if(fleetBusy||fleetSnapshots.length<2)return;fleetBusy=true;fleetError=null;render();try{fleetReport=await json('/api/fleet',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({snapshots:fleetSnapshots})});}catch(error){fleetReport=null;fleetError=error.message;}finally{fleetBusy=false;render();}},'primary');compare.disabled=fleetBusy||fleetSnapshots.length<2;append(controls,label,upload,compare);wrap.append(controls,el('p',`${fleetSnapshots.length} ${t('fleetSelected')}`,'muted'));if(fleetError)wrap.append(el('p',fleetError,'notice'));if(!fleetReport){empty(wrap,'fleetEmpty');$('view').append(wrap);return;}wrap.append(el('p',t('fleetCoverageNote'),'muted coverage-note'));const data=fleetReport.data,cards=el('div',null,'cards');[['fleetHosts',data.hosts.length],['fleetSnapshots',data.hosts.reduce((total,host)=>total+host.snapshotCount,0)],['fleetMedianCpu',`${number(data.medianCpuUsedPercent)}%`],['fleetMedianMemory',`${number(data.medianMemoryUsedPercent)}%`]].forEach(([label,value])=>{const card=el('article',null,'card');append(card,el('div',t(label),'card-label'),el('p',value,'card-value'));cards.append(card);});append(wrap,cards,el('p',`${t('fleetMedianDisk')}: ${data.medianMaximumDiskUsedPercent===null||data.medianMaximumDiskUsedPercent===undefined?'—':number(data.medianMaximumDiskUsedPercent)+'%'} · ${t('fleetFindings')}: ${fleetReport.findings.length}`,'muted'),table(['host','fleetSnapshots','cpu','memory','disk','findings','failedServices'],data.hosts.map(host=>[host.host,host.snapshotCount,`${number(host.cpuUsedPercent)}%`,`${number(host.memoryUsedPercent)}%`,host.maximumDiskUsedPercent===null||host.maximumDiskUsedPercent===undefined?'—':`${number(host.maximumDiskUsedPercent)}%`,host.findings,host.failedServices])),el('h2',t('fleetOutliers')),findingsList(fleetReport.findings));if(fleetReport.warnings?.length){const warnings=el('ul',null,'warning-text');fleetReport.warnings.forEach(warning=>warnings.append(el('li',warning)));wrap.append(warnings);}$('view').append(wrap);}

function showHistory() {
    const wrap = panel(t('retained'));
    wrap.append(el('p', t('historyNote'), 'muted'));
    const windows = [['15m','last15m'],['1h','last1h'],['24h','last24h'],['7d','last7d']];
    wrap.append(optionFilter('history-range','historyRange',windows.map(([key,label])=>[key,t(label)]),historyRange,value=>{historyRange=value;tablePages.clear();render();},'allHistory'));
    const duration = {'15m':900000,'1h':3600000,'24h':86400000,'7d':604800000}[historyRange];
    const visibleEntries = duration ? entries.filter(item=>Date.parse(item.collectedAtUtc)>=Date.now()-duration) : entries;
    if (!visibleEntries.length) empty(wrap,'noSamplesInRange');
    wrap.append(paginate(visibleEntries, pageEntries => {
        const timeline = el('ol', null, 'timeline');
        pageEntries.forEach(item => {
            const row = el('li'), time = el('time', date(item.collectedAtUtc));
            time.dateTime = item.collectedAtUtc;
            append(row, time, el('p', `${t('cpu')}: ${number(item.cpuUsedPercent)}% · ${t('memory')}: ${number(item.memoryUsedPercent)}% · ${item.findingCount} ${t('sampleFindings')}`), button(t('viewSample'), async () => {
                try { selectedSample = await json(`/api/history/${encodeURIComponent(item.id)}`); render(); }
                catch (error) { notice(error.message); }
            }));
            timeline.append(row);
        });
        return timeline;
    }, 'history:samples'));
    if (timelineReport?.data?.events) {
        wrap.append(el('h2', t('observedTimeline')), paginate(timelineReport.data.events, events => {
            const observed = el('ol', null, 'timeline');
            events.forEach(event => {
                const item = el('li'), time = el('time', date(event.timestampUtc)); time.dateTime = event.timestampUtc;
                append(item, time, el('h3', event.kind), el('p', event.description), el('small', event.source)); observed.append(item);
            });
            return observed;
        }, 'history:events'));
        reportWarnings(wrap, timelineReport.warnings);
    }
    $('view').append(chart(), wrap);
    if (selectedSample) {
        const sample = panel(t('redactedSample'));
        append(sample, el('p', `${t('retainedSource')}: ${date(selectedSample.collectedAtUtc)} · ${t('alwaysRedacted')}`, 'muted'),snapshotSummary(selectedSample));
        if (selectedSample.collectionWarnings?.length) reportWarnings(sample,selectedSample.collectionWarnings);
        const raw = el('details'); raw.open=true;
        append(raw,el('summary',t('rawJson')),el('pre',JSON.stringify(selectedSample,null,2),'evidence'));sample.append(raw);
        $('view').append(sample);
    }
}
function validatedCloudActions() {
    const candidates = cloudCatalog?.actions || capabilities.cloud.map(actionKey => {
        const parts = actionKey.split('/'), match = /^([a-z]+)(?:-scope-[1-9][0-9]*)?$/.exec(parts[0]);
        return {actionKey,providerId:match?.[1],scopeAlias:parts[0],operation:parts[1],availability:'configured',supported:true,readOnly:true};
    });
    return candidates.filter(action => {
        if (!action || !knownProviders.has(action.providerId) || !knownOperations.has(action.operation) || action.availability !== 'configured' || action.supported !== true || action.readOnly !== true) return false;
        if (typeof action.actionKey !== 'string' || !capabilities.cloud.includes(action.actionKey)) return false;
        const parts=action.actionKey.split('/');
        return parts.length===2 && parts[1]===action.operation && parts[0]===action.scopeAlias && new RegExp('^'+action.providerId+'(?:-scope-[1-9][0-9]*)?$').test(action.scopeAlias);
    });
}
function providerDescriptors() {
    const names={azure:'Microsoft Azure',aws:'Amazon Web Services',gcp:'Google Cloud',oci:'Oracle Cloud',digitalocean:'DigitalOcean',hetzner:'Hetzner Cloud',cloudflare:'Cloudflare',openstack:'OpenStack',alibaba:'Alibaba Cloud',ibm:'IBM Cloud',scaleway:'Scaleway'};
    return [...knownProviders].map(id=>{
        const descriptor=cloudCatalog?.providers?.find(item=>item.id===id);
        return {id,displayName:descriptor?.displayName || names[id],category:descriptor?.category || '',operations:Array.isArray(descriptor?.operations)?descriptor.operations:[]};
    });
}
async function runCloudQuery(action) {
    if(cloudBusy || !validatedCloudActions().some(item=>item.actionKey===action.actionKey))return;
    const version=++cloudVersion; cloudAction=action.actionKey;cloudBusy=true;cloudError=null;cloudResult=null;render();
    try {const result=await json(`/api/cloud/${action.scopeAlias}/${action.operation}`,{method:'POST'});if(version===cloudVersion)cloudResult=result;}
    catch(error){if(version===cloudVersion){cloudError=`${t('cloudFailed')} ${error.status===504?t('cloudTimeout'):error.status===403?t('cloudDenied'):error.message}`;cloudResult=error.report||null;}}
    finally{if(version===cloudVersion){cloudBusy=false;render();}}
}
function normalizedCoverage(status) {
    const key=String(status || '').replace(/[_\s-]/g,'').toLowerCase();
    return {complete:'complete',succeeded:'complete',success:'complete',partial:'partial',notconfigured:'notConfigured',notrequested:'notRequested',denied:'denied',permissiondenied:'denied',unauthorized:'denied',ratelimited:'rateLimited',failed:'failed',unsupported:'unsupported',timedout:'timed-out',configured:'configured',nodata:'noDataCoverage',unavailable:'failed'}[key] || null;
}
function cloudStatus(status) {return t(normalizedCoverage(status) || 'unknown');}
function resourceState(resource) {
    for(const object of [resource,resource.properties]){
        if(!object || typeof object!=='object')continue;
        const entry=Object.entries(object).find(([key,value])=>['state','status','lifecyclestate','provisioningstate','powerstate'].includes(key.replace(/[_-]/g,'').toLowerCase())&&['string','number','boolean'].includes(typeof value));
        if(entry)return String(entry[1]);
    }return t('unknown');
}

function cloudMetricSeries(series) {
    const group=el('section',null,'report-group');append(group,el('h3',t('cloudMetrics')),el('p',t('cloudMetricsNote'),'muted'));
    const valid=series.filter(item=>item&&typeof item==='object'&&(Array.isArray(item.points)||Array.isArray(item.samples)));
    group.append(el('p',`${t('showing')} ${Math.min(valid.length,10)} / ${valid.length}`,'muted'));
    valid.slice(0,10).forEach((item,index)=>{
        const percentUnit=['%','percent','percentage'].includes(String(item.unit).toLowerCase()), periodSeconds=item.samplingPeriodSeconds ?? item.periodSeconds;
        const section=el('section',null,'ops-cloud-series'), points=(item.points || item.samples).filter(point=>Number.isFinite(Date.parse(point.timeUtc || point.timestampUtc))&&typeof point.value==='number'&&Number.isFinite(point.value)&&(!percentUnit||(point.value>=0&&point.value<=100))).map(point=>({time:Date.parse(point.timeUtc || point.timestampUtc),value:point.value})).sort((a,b)=>a.time-b.time).slice(-720);
        const title=el('h4',`${item.metric || t('metric')} · ${item.unit || t('unknown')}`);title.id=`cloud-series-${index}`;section.append(title);
        const latest=points[points.length-1];
        section.append(facts([['source',item.source || cloudResult.kind],['scope',item.region || t('unknown')],['unit',item.unit || t('unknown')],['aggregation',item.aggregation || t('unknown')],['samplingPeriod',Number.isFinite(periodSeconds)?`${periodSeconds} s`:t('unknown')],['providerLag',latest?`${Math.max(0,Math.floor((Date.now()-latest.time)/1000))} s · ${date(new Date(latest.time).toISOString())}`:t('noData')]]));
        if(points.length<2){empty(section,'cloudNeedSamples');group.append(section);return;}
        const ns='http://www.w3.org/2000/svg',svg=document.createElementNS(ns,'svg');svg.setAttribute('viewBox','0 0 800 220');svg.setAttribute('role','img');svg.setAttribute('aria-labelledby',title.id);svg.classList.add('ops-chart__svg');
        const start=points[0].time,end=points[points.length-1].time,span=end-start || 1;
        const minimum=Math.min(...points.map(point=>point.value)),maximum=Math.max(...points.map(point=>point.value));
        const low=percentUnit?0:minimum,high=percentUnit?100:maximum===minimum?minimum+1:maximum;
        const add=(tag,attrs,text)=>{const node=document.createElementNS(ns,tag);Object.entries(attrs).forEach(([key,value])=>node.setAttribute(key,String(value)));if(text!==undefined)node.textContent=text;svg.append(node);return node;};
        const draw=()=>{
            if(!svg.isConnected){cloudPlotRenderers.delete(draw);return;}
            const viewport=Math.max(160,Math.min(2400,Math.round(svg.getBoundingClientRect().width || 800))),left=65,right=viewport-20,width=right-left;
            svg.setAttribute('viewBox',`0 0 ${viewport} 220`);svg.replaceChildren();
            for(const ratio of [0,.5,1]){const y=20+ratio*160;add('line',{x1:left,x2:right,y1:y,y2:y,stroke:'currentColor',opacity:'.2'});add('text',{x:left-9,y:y+4,'text-anchor':'end',fill:'currentColor','font-size':12},number(high-(high-low)*ratio));}
            let path='',previous=null;const period=Number.isFinite(periodSeconds)&&periodSeconds>0?periodSeconds*1000:null;
            points.forEach(point=>{const x=left+(point.time-start)/span*width,y=20+(high-point.value)/(high-low)*160;const continuous=previous&&point.time>previous.time&&period!==null&&point.time-previous.time<=period*2.5;path+=(continuous?' L ':' M ')+x.toFixed(2)+' '+y.toFixed(2);if(!continuous)add('circle',{cx:x,cy:y,r:2.5,fill:'var(--accent)'});previous=point;});
            add('path',{d:path,fill:'none',stroke:'var(--accent)','stroke-width':2.5});
            const format={hour:'2-digit',minute:'2-digit'};
            add('text',{x:left,y:210,fill:'currentColor','font-size':12},new Date(start).toLocaleTimeString(lang,format));add('text',{x:right,y:210,fill:'currentColor','text-anchor':'end','font-size':12},new Date(end).toLocaleTimeString(lang,format));
        };
        section.append(svg);cloudPlotRenderers.add(draw);queueMicrotask(draw);
        const details=el('details');append(details,el('summary',`${t('evidence')} · ${t('showing')} ${Math.min(points.length,50)} / ${points.length}`),table(['observation','value','unit'],points.slice(-50).map(point=>[date(new Date(point.time).toISOString()),point.value,item.unit || t('unknown')]),`cloud:metrics:${index}`));section.append(details);group.append(section);
    });return group;
}
function showCloud() {
    const wrap=panel(t('cloud')), providers=providerDescriptors(), actions=validatedCloudActions(), controls=el('div',null,'control-row');
    append(wrap,el('p',t('cloudCatalogNote'),'muted'),el('p',t(actions.length?'cloudNote':'cloudUnavailable'),'muted workspace-note'));
    controls.append(optionFilter('cloud-provider','provider',providers.map(item=>[item.id,item.displayName]),cloudProvider,value=>{cloudProvider=value;cloudScope='all';cloudAction=null;cloudResult=null;cloudError=null;render();},'allProviders'));
    const scopes=[...new Set(actions.filter(action=>cloudProvider==='all'||action.providerId===cloudProvider).map(action=>action.scopeAlias))];
    controls.append(optionFilter('cloud-scope','scope',scopes.map(alias=>[alias,alias]),cloudScope,value=>{cloudScope=value;cloudAction=null;cloudResult=null;cloudError=null;render();},'allScopes'));
    controls.querySelectorAll('select').forEach(select=>select.disabled=cloudBusy);wrap.append(controls);
    const cards=el('div',null,'ops-cloud-matrix');
    providers.filter(provider=>cloudProvider==='all'||provider.id===cloudProvider).forEach(provider=>{
        const card=el('section',null,'ops-cloud-card'), configured=actions.filter(action=>action.providerId===provider.id&&(cloudScope==='all'||action.scopeAlias===cloudScope));
        append(card,el('h3',provider.displayName));
        const status=el('span',cloudStatus(configured.length?'configured':'not-configured'),'ops-cloud-status');status.dataset.state=configured.length?'configured':'notConfigured';card.append(status);
        if(!configured.length)card.append(el('p',t('cloudNoScope'),'muted'));
        const coverage=el('div',null,'status-counts');
        ['inventory','health','posture','metrics','cost','patches'].forEach(operation=>{
            const capability=provider.operations.find(item=>item.name===operation), enabled=configured.some(action=>action.operation===operation);
            const state=enabled?'configured':capability?'not-configured':'unsupported', item=el('span',`${operation}: ${cloudStatus(state)}`,'ops-cloud-status');item.dataset.state=state;
            if(capability?.limitations?.length)item.title=capability.limitations.join(' ');coverage.append(item);
        });card.append(coverage);
        const buttons=el('div',null,'ops-cloud-actions');
        configured.forEach(action=>{const query=button(`${t('run')} · ${action.actionKey}`,()=>runCloudQuery(action));query.disabled=cloudBusy;buttons.append(query);});card.append(buttons);cards.append(card);
    });wrap.append(cards);
    if(cloudAction)wrap.append(el('p',`${t('source')}: ${cloudAction} · ${t('alwaysRedacted')}`,'source-badge'));
    if(cloudBusy){const status=el('p',t('cloudLoading'),'work-status');status.id='cloud-status';status.setAttribute('role','status');wrap.append(status);}
    else if(cloudError){const error=el('p',cloudError,'notice');error.id='cloud-error';error.setAttribute('role','alert');wrap.append(error);}
    else if(!cloudResult&&actions.length)empty(wrap,'cloudEmpty');
    if(cloudResult){
        const data=cloudResult.data, success=cloudResult.operationSucceeded!==false;
        const state=normalizedCoverage(data?.coverage?.state)||(!success?'failed':cloudResult.warnings?.length?'partial':'complete');
        const count=Number.isInteger(data?.coverage?.enumeratedResources)?data.coverage.enumeratedResources:Number.isInteger(data?.resourceCount)?data.resourceCount:Array.isArray(data?.resources)?data.resources.length:null;
        const visibleCount=['complete','partial'].includes(state)&&count!==null?state==='partial'?`${count} · ${t('observedOnly')}`:count:t('unknown');
        const summary=el('section',null,'ops-cloud-result-summary');summary.append(el('h3',t('cloudResult')));
        const badge=el('span',cloudStatus(state),'ops-cloud-status');badge.dataset.state=state;summary.append(badge);
        summary.append(facts([['source',cloudResult.kind || cloudAction],['cloudObserved',date(data?.coverage?.observedAtUtc || cloudResult.collectedAtUtc)],['resourceCount',visibleCount]]));
        if(state==='partial')summary.append(el('p',t('observedOnly'),'coverage-note muted'));
        else if(!['complete'].includes(state))summary.append(el('p',t(state==='denied'?'cloudDenied':state==='timed-out'?'cloudTimeout':'cloudFailedCoverage'),'coverage-note muted'));
        else if(count===0&&!cloudAction?.endsWith('/metrics'))summary.append(el('p',t('cloudEmptyCoverage'),'coverage-note muted'));
        reportWarnings(summary,cloudResult.warnings);
        if(cloudResult.findings?.length)summary.append(findingsList(cloudResult.findings,'cloud:findings'));
        if(Array.isArray(data?.metrics))summary.append(cloudMetricSeries(data.metrics));
        const resources=Array.isArray(data?.resources)?data.resources:[];
        if(resources.length)summary.append(table(['provider','name','category','state'],resources.map(item=>[item.provider || cloudAction?.split('/')[0],item.name || item.id,item.type,resourceState(item)]),'cloud:resources'));
        const raw=el('details');raw.open=true;append(raw,el('summary',t('rawJson')),el('pre',JSON.stringify(cloudResult,null,2),'evidence'));summary.append(raw);wrap.append(summary);
    }
    $('view').append(wrap);
}

function showPolicy(){const wrap=panel(t('policy'));wrap.append(el('p',t('policyNote'),'muted'));if(!capabilities.policy)wrap.append(el('p',t('policyUnavailable'),'muted'));const label=el('label',t('policyDraft'),'editor-label'),editor=el('textarea');editor.id='policy-editor';editor.value=policyYaml;editor.spellcheck=false;editor.autocomplete='off';editor.setAttribute('autocapitalize','off');editor.setAttribute('aria-describedby','policy-preview-note');label.htmlFor=editor.id;const editorWrap=el('div',null,'policy-editor-wrap'),lineNumbers=el('pre',null,'policy-lines');lineNumbers.setAttribute('aria-hidden','true');lineNumbers.textContent=policyYaml.split('\n').map((_,index)=>index+1).join('\n');append(editorWrap,lineNumbers,editor);editor.addEventListener('scroll',()=>{lineNumbers.scrollTop=editor.scrollTop;});const note=el('p',t('policyNote'),'muted');note.id='policy-preview-note';editor.addEventListener('input',()=>{policyYaml=editor.value;lineNumbers.textContent=policyYaml.split('\n').map((_,index)=>index+1).join('\n');policyValidatedText=null;policyPreview=null;policyError=null;const result=document.getElementById('policy-result');if(result)result.replaceChildren(el('p',t('policyChanged'),'muted'));const download=document.getElementById('policy-download');if(download)download.disabled=true;});const controls=el('div',null,'control-row');const preview=button(t('previewPolicy'),async event=>{if(policyBusy)return;const submitted=policyYaml;policyBusy=true;event.currentTarget.disabled=true;policyError=null;try{const response=await api('/api/policy/preview',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text:submitted})});const result=await response.json();policyPreview=submitted===policyYaml?result:null;policyValidatedText=submitted===policyYaml?submitted:null;notice('');}catch(error){if(submitted===policyYaml){policyPreview=null;policyValidatedText=null;policyError=error.message;}}finally{policyBusy=false;render();}},'primary'),download=button(t('downloadPolicy'),()=>{if(policyValidatedText===policyYaml)saveBlob(new Blob([policyYaml],{type:'application/yaml'}),'opscope.yml');});preview.disabled=policyBusy;download.id='policy-download';download.disabled=policyValidatedText!==policyYaml;append(controls,preview,download);append(wrap,label,editorWrap,note,el('p',policyValidatedText===policyYaml?t('policyValid'):policyError?t('policyInvalid'):t('policyDraftState'),'source-badge'),controls);const outcome=el('div');outcome.id='policy-result';wrap.append(outcome);if(policyError)outcome.append(el('p',`${t('policyInvalid')}: ${policyError}`,'notice'));if(policyPreview){outcome.append(el('h3',t('policyValid')),el('p',`${t('collected')}: ${date(policyPreview.collectedAtUtc)}`,'muted'),findingsList(policyPreview.findings));if(policyPreview.warnings?.length){const warnings=el('ul');policyPreview.warnings.forEach(w=>warnings.append(el('li',w)));outcome.append(warnings);}}if(policyResult){const configured=el('details');append(configured,el('summary',t('configuredPolicy')),el('pre',JSON.stringify(policyResult,null,2),'evidence'));wrap.append(configured);}$('view').append(wrap);}

function analysisBody(operation) {
    if (!analysisSnapshot) throw new Error(t('analysisSelect'));
    const request = {snapshot: analysisSnapshot, operation};
    if (operation === 'triage') request.scenario = analysisScenario;
    if (operation === 'ioc') {
        if (utf8Length(analysisIndicatorText) > indicatorLimit) throw new Error(t('indicatorLimit'));
        request.indicators = {format: analysisIndicatorFormat, text: analysisIndicatorText};
    }
    if (operation === 'timeline' && analysisBaseline) request.baseline = analysisBaseline;
    return boundedBody(request);
}
function boundedBody(value) {
    const body = JSON.stringify(value);
    if (utf8Length(body) > requestLimit) throw new Error(t('analysisRequestLimit'));
    return body;
}
async function readUtf8File(file, limit, message) {
    if (file.size > limit) throw new Error(t(message));
    try { return new TextDecoder('utf-8', {fatal:true}).decode(await file.arrayBuffer()); }
    catch { throw new Error(t(message === 'indicatorLimit' ? 'indicatorLimit' : 'invalidFile')); }
}
function analysisRequest(body, signal) {
    return json('/api/analyze', {method:'POST', headers:{'Content-Type':'application/json'}, body, signal});
}
function invalidateAnalysis() {
    analysisReport = null;
    analysisError = null;
    $('analysis-error')?.remove();
    const result = $('analysis-result');
    if (result) result.replaceChildren(el('p', t('analysisChanged'), 'muted'));
    const download = $('analysis-download');
    if (download) download.disabled = analysisOperation !== 'inspect' || !analysisSafe;
}
function clearAnalysis() {
    // EN: Invalidate pending responses before discarding data so a late request cannot restore cleared evidence.
    // ES: Se invalidan las respuestas pendientes antes de borrar datos para que una petición tardía no restaure la evidencia.
    analysisVersion++;
    analysisController?.abort();
    analysisController = null;
    analysisSnapshot = analysisSafe = analysisBaseline = analysisBaselineSafe = analysisReport = null;
    analysisIndicatorText = '';
    analysisBusy = false;
    analysisError = null;
    tablePages.clear();
    render();
}
async function openAnalysisSnapshot(file, isBaseline = false) {
    if (!file) return;
    const version = ++analysisVersion;
    analysisController?.abort();
    analysisController = new AbortController();
    const signal = analysisController.signal;
    analysisBusy = true;
    analysisError = null;
    analysisReport = null;
    if (isBaseline) analysisBaseline = analysisBaselineSafe = null;
    else analysisSnapshot = analysisSafe = analysisBaseline = analysisBaselineSafe = null;
    render();
    try {
        const content = (await readUtf8File(file, requestLimit, 'maxFile')).replace(/^\uFEFF/, '');
        if (version !== analysisVersion) return;
        let parsed;
        try { parsed = JSON.parse(content); } catch { throw new Error(t('invalidFile')); }
        // Preserve the original JSON for the shared strict parser, including duplicate members.
        const inspectBody = '{"snapshot":' + content + ',"operation":"inspect"}';
        if (utf8Length(inspectBody) > requestLimit) throw new Error(t('analysisRequestLimit'));
        const safe = await analysisRequest(inspectBody, signal);
        if (version !== analysisVersion) return;
        if (isBaseline) { analysisBaseline = parsed; analysisBaselineSafe = safe; }
        else { analysisSnapshot = parsed; analysisSafe = safe; }
        tablePages.clear();
    } catch (error) {
        if (version === analysisVersion && error.name !== 'AbortError') analysisError = error.message;
    } finally {
        if (version === analysisVersion) { analysisBusy = false; analysisController = null; render(); }
    }
}
async function runAnalysis() {
    // EN: Send the selected saved source; live refresh must not substitute host data or overwrite this draft.
    // ES: Se envía la fuente guardada seleccionada; el refresco en vivo no debe sustituirla ni sobrescribir el borrador.
    if (analysisBusy || !analysisSafe) return;
    const version = ++analysisVersion;
    analysisController = new AbortController();
    analysisBusy = true;
    analysisError = null;
    analysisReport = null;
    render();
    try {
        const result = await analysisRequest(analysisBody(analysisOperation), analysisController.signal);
        if (version !== analysisVersion) return;
        if (analysisOperation === 'inspect') analysisSafe = result;
        else analysisReport = result;
        tablePages.clear();
    } catch (error) {
        if (version === analysisVersion && error.name !== 'AbortError') analysisError = error.message;
    } finally {
        if (version === analysisVersion) { analysisBusy = false; analysisController = null; render(); }
    }
}
function selectControl(id, label, choices, value, onChange) {
    const group = el('div', null, 'field'), caption = el('label', t(label)), select = el('select');
    caption.htmlFor = id;
    select.id = id;
    choices.forEach(([key, text]) => { const option = el('option', text || t(key)); option.value = key; select.append(option); });
    select.value = value;
    select.disabled = analysisBusy;
    select.addEventListener('change', () => onChange(select.value));
    append(group, caption, select);
    return group;
}
function analysisFile(id, label, onFile, accept = '.json,application/json') {
    const group = el('div', null, 'field'), caption = el('label', t(label)), input = el('input');
    caption.htmlFor = id;
    input.type = 'file'; input.id = id; input.accept = accept; input.disabled = analysisBusy;
    input.addEventListener('change', () => onFile(input.files[0]));
    append(group, caption, input);
    return group;
}
function snapshotSummary(value) {
    return facts([['collected', date(value.collectedAtUtc)], ['host', value.host.hostname], ['platform', value.host.platform],
        ['cpu', `${number(value.cpuUsedPercent)}%`], ['memory', `${number(value.memory.usedPercent)}%`],
        ['processes', value.processes.length], ['listeners', value.listeners.length], ['services', value.services.length]]);
}
function showAnalysisResult(target) {
    if (analysisOperation === 'inspect' && analysisSafe) {
        append(target, el('h2', t('analysisSnapshot')), findingsList(analysisSafe.findings, 'analysis:inspect:findings'));
        const sections = [
            ['processList', ['pid','name','user','workingSet','cpuTime','command'], analysisSafe.processes.map(p => [p.id,p.name,p.user,number(p.workingSetMb),p.cpuTime,p.commandLine])],
            ['portList', ['protocol','address','process','source'], analysisSafe.listeners.map(p => [p.protocol,p.localAddress,p.process,p.source])],
            ['services', ['name','state','serviceDescription','source'], analysisSafe.services.map(s => [s.name,s.state,s.description,s.source])]
        ];
        sections.forEach(([title, headers, rows]) => {
            const details = el('details'), summary = el('summary', `${t(title)} · ${rows.length}`);
            append(details, summary, table(headers, rows, `analysis:${title}`)); target.append(details);
        });
        const raw = el('details');
        append(raw, el('summary', t('evidence')), el('pre', JSON.stringify(analysisSafe, null, 2), 'evidence')); target.append(raw);
        reportWarnings(target, analysisSafe.collectionWarnings);
        return;
    }
    if (!analysisReport) { target.append(el('p', t('analysisChanged'), 'empty')); return; }
    append(target, el('h2', t('analysisResult')), el('p', t('analysisResultNote'), 'muted'));
    const report = analysisReport, data = report.data || {};
    if (report.kind === 'triage') {
        const steps = el('ol', null, 'triage-steps');
        (data.steps || []).forEach(step => {
            const item = el('li');
            append(item, el('h3', step.title), el('p', step.evidence, 'muted'), el('p', step.guidance)); steps.append(item);
        });
        target.append(steps);
    } else if (report.kind === 'ioc') {
        target.append(facts([['indicators', data.indicatorCount], ['observables', data.observableCount], ['matches', (data.matches || []).length]]),
            table(['indicator','source','evidence'], (data.matches || []).map(item => [
                `${item.indicator.type}: ${item.indicator.value}${item.indicator.label ? ` · ${item.indicator.label}` : ''}`, item.source, item.evidence
            ]), 'analysis:ioc'));
    } else if (report.kind === 'timeline') {
        target.append(table(['collected','category','source','details'], (data.events || []).map(event => [date(event.timestampUtc),event.kind,event.source,event.description]), 'analysis:timeline'));
    }
    append(target, el('h3', t('findings')), findingsList(report.findings || [], `analysis:${report.kind}:findings`));
    reportWarnings(target, report.warnings);
}
function reportWarnings(target, warnings) {
    if (!warnings?.length) return;
    const details = el('details'), list = el('ul', null, 'warning-text');
    warnings.forEach(warning => list.append(el('li', warning)));
    append(details, el('summary', `${t('warnings')} · ${warnings.length}`), list); details.open = true; target.append(details);
}
async function openIndicators(file) {
    if (!file || analysisBusy) return;
    const version = ++analysisVersion;
    analysisBusy = true;
    analysisError = null;
    analysisReport = null;
    render();
    try {
        const content = await readUtf8File(file, indicatorLimit, 'indicatorLimit');
        if (version !== analysisVersion) return;
        if (utf8Length(content) > indicatorLimit) throw new Error(t('indicatorLimit'));
        analysisIndicatorText = content;
        if (/\.json$|\.stix$/i.test(file.name)) analysisIndicatorFormat = 'stix';
        else if (/\.csv$/i.test(file.name)) analysisIndicatorFormat = 'csv';
    } catch (error) {
        if (version === analysisVersion) analysisError = error.message;
    } finally {
        if (version === analysisVersion) { analysisBusy = false; render(); }
    }
}
async function exportAnalysisSnapshot() {
    if (!analysisSafe || analysisBusy) return;
    if (analysisExportFormat === 'json') {
        saveBlob(new Blob([JSON.stringify(analysisSafe, null, 2)], {type:'application/json'}), 'opscope-saved-redacted-snapshot.json');
        return;
    }
    const version = ++analysisVersion;
    analysisController = new AbortController();
    analysisBusy = true;
    analysisError = null;
    render();
    try {
        const response = await api('/api/report', {method:'POST', headers:{'Content-Type':'application/json'}, body:boundedBody({snapshot:analysisSnapshot, format:analysisExportFormat}), signal:analysisController.signal});
        const blob = await response.blob();
        if (version === analysisVersion) saveBlob(blob, `opscope-saved-redacted-report.${analysisExportFormat === 'junit' ? 'xml' : analysisExportFormat}`);
    } catch (error) {
        if (version === analysisVersion && error.name !== 'AbortError') analysisError = error.message;
    } finally {
        if (version === analysisVersion) { analysisBusy = false; analysisController = null; render(); }
    }
}
function showAnalysis() {
    const setup = panel(t('analysis'));
    const progress=el('ol',null,'analysis-progress');
    ['stepFile','stepValidate','stepMode','stepRun','stepResult'].forEach((key,index)=>{const item=el('li',t(key));item.dataset.complete=String(index<2?Boolean(analysisSafe):index===2?Boolean(analysisSafe):index===3?Boolean(analysisReport):Boolean(analysisReport)||(analysisOperation==='inspect'&&Boolean(analysisSafe)));progress.append(item);});setup.append(progress);
    append(setup, el('p', t('analysisNote'), 'muted'), el('p', t('analysisLimits'), 'muted workspace-note'));
    const upload = el('div', null, 'control-row');
    const clear = button(t('analysisClear'), clearAnalysis); clear.id = 'analysis-clear';
    append(upload, analysisFile('analysis-upload', 'analysisUpload', file => openAnalysisSnapshot(file)), clear);
    setup.append(upload);
    if (analysisBusy) {
        const status = el('p', t(analysisSafe ? 'analysisRunning' : 'analysisLoading'), 'work-status');
        status.setAttribute('role', 'status'); setup.append(status);
    }
    if (analysisError) {
        const error = el('p', analysisError, 'notice'); error.id = 'analysis-error'; error.setAttribute('role','alert'); setup.append(error);
    }
    if (!analysisSafe) { empty(setup, 'analysisEmpty'); $('view').append(setup); return; }
    const context = el('div', null, 'saved-summary');
    append(context, el('span', `${t('analysisReady')} · ${t('alwaysRedacted')}`, 'source-badge'), snapshotSummary(analysisSafe));
    setup.append(context);
    const controls = el('div', null, 'analysis-controls');
    controls.append(selectControl('analysis-operation', 'analysisOperation', ['inspect','triage','ioc','timeline'].map(key => [key]), analysisOperation, value => {
        analysisOperation = value; invalidateAnalysis(); render();
    }));
    if (analysisOperation === 'triage') controls.append(selectControl('analysis-scenario', 'scenario', ['high-cpu','disk-full','port-exposed'].map(key => [key]), analysisScenario, value => { analysisScenario = value; invalidateAnalysis(); }));
    setup.append(controls);
    if (analysisOperation === 'ioc') {
        const iocControls = el('div', null, 'control-row');
        append(iocControls, selectControl('analysis-ioc-format', 'indicatorFormat', [['csv','CSV'],['stix','STIX 2.x JSON']], analysisIndicatorFormat, value => { analysisIndicatorFormat = value; invalidateAnalysis(); render(); }),
            analysisFile('analysis-ioc-upload', 'indicatorUpload', openIndicators, '.csv,.json,.stix,text/csv,application/json'));
        const label = el('label', t('indicatorText'), 'editor-label'), editor = el('textarea');
        label.htmlFor = 'analysis-ioc-text'; editor.id = 'analysis-ioc-text'; editor.value = analysisIndicatorText;
        editor.disabled = analysisBusy; editor.spellcheck = false; editor.autocomplete = 'off'; editor.maxLength = indicatorLimit;
        editor.placeholder = analysisIndicatorFormat === 'csv' ? 'type,value,label\nip,203.0.113.10,Example' : '{"type":"bundle","objects":[]}';
        editor.setAttribute('aria-describedby','analysis-ioc-hint analysis-ioc-size');
        const size = el('p', `${utf8Length(analysisIndicatorText)} / ${indicatorLimit} ${t('bytes')}`, 'muted');
        size.id = 'analysis-ioc-size'; size.setAttribute('role','status');
        editor.addEventListener('input', () => {
            analysisIndicatorText = editor.value; invalidateAnalysis();
            const tooLarge = utf8Length(analysisIndicatorText) > indicatorLimit;
            editor.setCustomValidity(tooLarge ? t('indicatorLimit') : '');
            size.textContent = tooLarge ? t('indicatorLimit') : `${utf8Length(analysisIndicatorText)} / ${indicatorLimit} ${t('bytes')}`;
            size.classList.toggle('warning-text', tooLarge);
            $('analysis-run').disabled = tooLarge || !analysisIndicatorText.trim();
        });
        const hint = el('p', t('indicatorHint'), 'muted'); hint.id = 'analysis-ioc-hint';
        append(setup, iocControls, label, editor, hint, size);
    }
    if (analysisOperation === 'timeline') {
        const baselineControls = el('div', null, 'control-row');
        baselineControls.append(analysisFile('analysis-baseline-upload', 'analysisBaseline', file => openAnalysisSnapshot(file, true)));
        if (analysisBaselineSafe) baselineControls.append(button(t('analysisBaselineRemoved'), () => { analysisBaseline = analysisBaselineSafe = null; invalidateAnalysis(); render(); }));
        append(setup, baselineControls, el('p', analysisBaselineSafe ? `${t('analysisBaselineReady')}: ${date(analysisBaselineSafe.collectedAtUtc)}` : t('analysisNoBaseline'), 'muted'), el('p', t('analysisTimelineNote'), 'muted workspace-note'));
    }
    const actions = el('div', null, 'control-row analysis-actions'), run = button(t('analysisRun'), runAnalysis, 'primary');
    run.id = 'analysis-run'; run.disabled = analysisBusy || (analysisOperation === 'ioc' && (!analysisIndicatorText.trim() || utf8Length(analysisIndicatorText) > indicatorLimit));
    const download = button(t('analysisDownload'), () => {
        const result = analysisOperation === 'inspect' ? analysisSafe : analysisReport;
        if (result) saveBlob(new Blob([JSON.stringify(result, null, 2)], {type:'application/json'}), `opscope-saved-redacted-${analysisOperation}.json`);
    });
    download.id = 'analysis-download'; download.disabled = analysisBusy || !(analysisOperation === 'inspect' ? analysisSafe : analysisReport);
    append(actions, run, download); setup.append(actions);
    const exports = el('div', null, 'control-row saved-exports');
    exports.append(selectControl('analysis-export-format','exportFormat', ['json','html','pdf','sarif','junit','csv','jsonl','cef'].map(key => [key,key.toUpperCase()]), analysisExportFormat, value => { analysisExportFormat = value; }));
    const exportButton = button(t('analysisExport'), exportAnalysisSnapshot); exportButton.id = 'analysis-export'; exportButton.disabled = analysisBusy; exports.append(exportButton); setup.append(exports);
    $('view').append(setup);
    const result = el('section', null, 'panel'); result.id = 'analysis-result'; result.setAttribute('aria-live','polite');
    showAnalysisResult(result); $('view').append(result);
}
function updateSourceContext() {
    const saved = view === 'analysis', redactedView = ['analysis','history','fleet','cloud'].includes(view), context = $('source-context');
    const label = saved ? 'savedSource' : view === 'history' ? 'retainedSource' : view === 'fleet' ? 'fleetSource' : view === 'cloud' ? 'cloudSource' : 'liveSource';
    let detail = snapshot ? date(snapshot.collectedAtUtc) : t('connecting');
    if (saved) detail = `${t('alwaysRedacted')} · ${analysisSafe ? date(analysisSafe.collectedAtUtc) : t('sourceEmpty')}`;
    else if (view === 'history') detail = `${t('alwaysRedacted')} · ${entries.length} ${t('retained')}`;
    else if (view === 'fleet') detail = `${t('alwaysRedacted')} · ${fleetSnapshots.length} ${t('fleetSelected')}`;
    else if (view === 'cloud') detail = `${t('alwaysRedacted')}${cloudAction ? ` · ${cloudAction}` : ''}`;
    if(pendingEvidence&&!redactedView)detail+=` · ${t('pendingEvidence')}`;
    context.replaceChildren(el('span', t(label), 'source-badge'), el('span', detail, 'muted'));
    context.classList.toggle('saved', redactedView);
    $('full').disabled = redactedView;
    document.querySelector('.full-toggle').hidden = redactedView;
    $('privacy').textContent = t(!redactedView && $('full').checked ? 'fullWarning' : 'redacted');
    context.setAttribute('aria-label', t('source'));
    $('collect').hidden = ['analysis','cloud','fleet','history'].includes(view);
    document.querySelector('.search-wrap').hidden = redactedView;
    $('page-description').textContent = t(saved ? 'analysisDescription' : 'description');
    if (redactedView) { $('search-results').hidden = true; $('search-results').replaceChildren(); }
}

function saveBlob(blob,name){const url=URL.createObjectURL(blob),link=el('a');link.href=url;link.download=name;document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),30000);}
async function download(path,name){const response=await api(path),blob=await response.blob();if(path==='/api/bundle'){const digest=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',await blob.arrayBuffer())),item=>item.toString(16).padStart(2,'0')).join('');if(digest!==response.headers.get('X-Checksum-Sha256'))throw new Error(t('error'));lastBundleChecksum=digest;const checksum=document.getElementById('bundle-checksum');if(checksum)checksum.disabled=false;}saveBlob(blob,name);}
function showReports() {
    const wrap=panel(t('reports'));
    const bundle=el('section',null,'report-group'), files=el('section',null,'report-group'), automation=el('section',null,'report-group');
    append(bundle,el('h3',t('reportBundle')));append(files,el('h3',t('reportInvestigate')));append(automation,el('h3',t('reportAutomate')));
    const bundleActions=el('div',null,'report-options'), fileActions=el('div',null,'report-options'), automationActions=el('div',null,'report-options');
    [['downloadBundle','/api/bundle','opscope-redacted-bundle.zip',bundleActions],['downloadJson','/api/snapshot','opscope-redacted-snapshot.json',fileActions],['downloadReport','/api/report','opscope-redacted-report.html',fileActions],['downloadPdf','/api/report?format=pdf','opscope-redacted-report.pdf',fileActions],['downloadSarif','/api/report?format=sarif','opscope-findings.sarif',automationActions]].forEach(([label,path,name,target])=>target.append(button(t(label),()=>download(path,name).catch(error=>notice(error.message)))));
    const checksum=button(t('downloadChecksum'),()=>{if(lastBundleChecksum)saveBlob(new Blob([lastBundleChecksum+'\n'],{type:'text/plain'}),'opscope-redacted-bundle.zip.sha256');});checksum.id='bundle-checksum';checksum.disabled=!lastBundleChecksum;bundleActions.append(checksum);
    fileActions.append(button(t('printReport'),async()=>{const popup=window.open('about:blank','_blank');if(!popup){notice(t('error'));return;}try{const content=await(await api('/api/report')).text(),url=URL.createObjectURL(new Blob([content],{type:'text/html'}));popup.location.href=url;popup.addEventListener('load',()=>popup.print(),{once:true});setTimeout(()=>URL.revokeObjectURL(url),60000);}catch(error){popup.close();notice(error.message);}}));
    append(bundle,bundleActions,el('p',t('checksumNote'),'muted'));files.append(fileActions);automation.append(automationActions);append(wrap,el('p',t('reportNote'),'muted'),bundle,files,automation);$('view').append(wrap);
}
function safeSettings() {
    const result={};
    for(const key of ['readOnly','redactedByDefault','historyRedacted','retentionCount','retentionDays','refreshSeconds','maxUploadBytes','telemetry','notifications']){
        if(typeof settings?.[key]==='boolean'||typeof settings?.[key]==='number')result[key]=settings[key];
    }
    if(settings?.listener==='127.0.0.1')result.listener=settings.listener;return result;
}
function showSettings() {
    const wrap=panel(t('settings'));wrap.append(el('p',t('settingsNote'),'muted'));
    const preferences=el('section',null,'report-group');preferences.append(el('h3',t('preferences')));
    preferences.append(optionFilter('density','density',[['standard',t('standardDensity')],['compact',t('compactDensity')],['comfortable',t('comfortableDensity')]],density,value=>{if(!['standard','compact','comfortable'].includes(value))return;density=value;document.documentElement.dataset.density=density;try{localStorage.setItem('opscope-density',density);}catch{}},'choose'));
    // This preference has no empty/default option; only the three known values can be persisted.
    preferences.querySelector('option[value=all]')?.remove();wrap.append(preferences);
    if(settings){wrap.append(el('h3',t('effectiveSettings')),table(['setting','value'],Object.entries(settings).map(([key,value])=>[key,String(value)])));
        wrap.append(button(t('copySettings'),async()=>{try{await navigator.clipboard.writeText(JSON.stringify(safeSettings(),null,2));notice(t('settingsCopied'));}catch{notice(t('copyFailed'));}}));}
    $('view').append(wrap);
}

function searchResults() {
    const target=$('search-results');target.replaceChildren();if(['analysis','history','fleet','cloud'].includes(view)){target.hidden=true;return;}
    const query=$('search').value.trim();target.hidden=!query;if(!query||!snapshot)return;
    const groups=[['findings',snapshot.findings.filter(match).map(item=>item.title)],['processes',snapshot.processes.filter(match).map(item=>`${item.name} · ${item.id}`)],['portList',snapshot.listeners.filter(match).map(item=>`${item.protocol} · ${item.localAddress}`)],['services',snapshot.services.filter(match).map(item=>`${item.name} · ${item.state}`)]];
    const total=groups.reduce((sum,[,rows])=>sum+rows.length,0);target.append(el('p',`${total} ${t('searchCount')} · ${t('showing')} ${Math.min(total,30)}`,'search-summary'));
    let remaining=30;
    groups.forEach(([section,rows])=>{if(!rows.length||remaining<=0)return;target.append(el('h2',`${t(section)} (${rows.length})`,'search-group'));for(const text of rows.slice(0,remaining)){const node=button(text,()=>{navigate(section==='portList'?'processes':section);target.hidden=true;$('content').focus();});node.append(el('small',t(section)));target.append(node);remaining--;}});
    if(!total)target.append(el('p',t('searchEmpty'),'empty'));
}

function render(reason = 'explicit') {
    const target=$('view'), active=document.activeElement;
    if(reason==='sample'&&(target.contains(active)||['policy','fleet','analysis','drift','cloud','reports','settings'].includes(view))){
        pendingEvidence=true;updateSourceContext();updateFreshness();return;
    }
    const focusedId=target.contains(active)?active.id:null;
    const selection=focusedId&&typeof active.selectionStart==='number'?{start:active.selectionStart,end:active.selectionEnd}:null;
    const scrolls=[...target.querySelectorAll('.table-wrap')].map(node=>({top:node.scrollTop,left:node.scrollLeft}));
    pendingEvidence=false;
    cloudPlotRenderers.clear();
    if(!['overview','history'].includes(view)){chartHandle?.dispose();chartHandle=null;chartNode=null;chartContext=null;}
    target.replaceChildren();
    updateSourceContext();
    updateCollectionControl();
    if (view === 'analysis' && token) {
        showAnalysis();
        $('collected-at').textContent = analysisSafe ? `${t('savedSource')}: ${date(analysisSafe.collectedAtUtc)}` : t('sourceEmpty');
        return;
    }
    if (!snapshot) { empty(target, token ? 'connecting' : 'noToken'); return; }
    const handlers = {overview, findings:showFindings, processes:showProcesses, services:showServices, drift:showDrift, fleet:showFleet, history:showHistory, cloud:showCloud, policy:showPolicy, reports:showReports, settings:showSettings};
    handlers[view]();
    $('finding-badge').textContent = snapshot.findings.length;
    $('collected-at').textContent = `${t('collected')}: ${date(snapshot.collectedAtUtc)}`;
    searchResults();
    if(focusedId){const next=$(focusedId);next?.focus({preventScroll:true});if(selection&&next?.setSelectionRange)next.setSelectionRange(selection.start,selection.end);}
    target.querySelectorAll('.table-wrap').forEach((node,index)=>{if(scrolls[index]){node.scrollTop=scrolls[index].top;node.scrollLeft=scrolls[index].left;}});
    updateFreshness();
}
function applyLiveSample(next, history, timeline, generation, version, wantsFull) {
    // EN: Recheck privacy and request generations after every await before showing identifiers.
    // ES: Se vuelven a comprobar la privacidad y las generaciones de petición tras cada await antes de mostrar identidades.
    if (generation !== privacyVersion || version !== snapshotVersion || wantsFull !== $('full').checked) return;
    snapshot = next;
    if (!wantsFull) safeSnapshot = next;
    entries = history;
    timelineReport = timeline;
    setConnection('connected');
    [...history].sort((a,b)=>Date.parse(a.collectedAtUtc)-Date.parse(b.collectedAtUtc)).forEach(sample=>window.OpscopeCharts?.push(sample));
    render('sample');
    $('finding-badge').textContent = next.findings.length;
}
async function refresh() {
    const generation = privacyVersion, version = ++snapshotVersion, wantsFull = $('full').checked;
    const [next, history, timeline] = await Promise.all([
        json(`/api/snapshot${wantsFull ? '?full=true' : ''}`), json('/api/history'), json('/api/timeline')
    ]);
    applyLiveSample(next, history, timeline, generation, version, wantsFull);
    if (generation === privacyVersion && version === snapshotVersion) render();
}
async function processStreamEvent(event) {
    const lines=event.split('\n'), type=lines.find(line=>line.startsWith('event:'))?.slice(6).trim() || 'snapshot';
    const data=lines.filter(line=>line.startsWith('data:')).map(line=>line.slice(5).replace(/^ /,'')).join('\n');
    if(!data)return;
    const parsed=JSON.parse(data);
    if(type==='metrics'){
        if(window.OpscopeCharts?.push(parsed))lastMetricSequence=Math.max(lastMetricSequence,Number(parsed.sequence)||0);
        return;
    }
    if(type==='metrics-gap'){
        if(Number.isSafeInteger(parsed?.droppedSamples)&&parsed.droppedSamples>0){
            notice(t('metricsGap'));
            if(!metricRecovery)metricRecovery=(async()=>{
                const history=await json(`/api/metrics/history?window=30m&limit=720&afterSequence=${lastMetricSequence}`);
                const samples=Array.isArray(history)?history:Array.isArray(history?.samples)?history.samples:[];
                for(const sample of samples)if(window.OpscopeCharts?.push(sample))lastMetricSequence=Math.max(lastMetricSequence,Number(sample.sequence)||0);
            })().catch(()=>{}).finally(()=>{metricRecovery=null;});
            await metricRecovery;
        }
        return;
    }
    if(type!=='snapshot'||!parsed||!Array.isArray(parsed.findings)||!parsed.memory)return;
    safeSnapshot=parsed;
    const generation=privacyVersion,version=++snapshotVersion,wantsFull=$('full').checked;
    const [next,history,timeline]=await Promise.all([
        wantsFull?json('/api/snapshot?full=true'):Promise.resolve(parsed),json('/api/history'),json('/api/timeline')
    ]);
    applyLiveSample(next,history,timeline,generation,version,wantsFull);
}
async function live() {
    while(!disposed&&token&&connectionState!=='disconnected'){
        let reader,watchdog;
        streamController=new AbortController();
        try{
            const headers=lastMetricSequence?{'Last-Event-ID':String(lastMetricSequence)}:{};
            const response=await api('/api/events',{signal:streamController.signal,headers});
            reader=response.body.getReader();lastTransportAt=Date.now();setConnection('connected');
            watchdog=setInterval(()=>{if(Date.now()-lastTransportAt>45000)streamController?.abort();},10000);
            const decoder=new TextDecoder();let buffer='';
            while(!disposed){
                const {done,value}=await reader.read();if(done)break;
                lastTransportAt=Date.now();streamFailures=0;
                buffer=(buffer+decoder.decode(value,{stream:true})).replace(/\r\n/g,'\n');
                if(buffer.length>4*1024*1024)throw new Error(t('error'));
                let split;
                while((split=buffer.indexOf('\n\n'))>=0){const event=buffer.slice(0,split);buffer=buffer.slice(split+2);await processStreamEvent(event);}
            }
        }catch(error){
            if(error.status===401||error.status===403){setConnection('disconnected');notice(t('errorAuth'));}
            else if(!disposed)setConnection('recovering');
        }finally{clearInterval(watchdog);try{await reader?.cancel();}catch{}streamController=null;}
        if(!disposed&&connectionState!=='disconnected'){
            setConnection('recovering');
            const backoff=Math.min(30000,1000*2**Math.min(streamFailures++,5))*(.8+Math.random()*.4);
            const cooldown=Math.max(0,cooldownUntil-Date.now());
            await new Promise(resolve=>setTimeout(resolve,Math.max(backoff,cooldown)));
        }
    }
}

document.querySelectorAll('.nav-item').forEach(node=>node.addEventListener('click',()=>navigate(node.dataset.view)));
document.querySelector('.brand').addEventListener('click',event=>{event.preventDefault();navigate('overview');$('content').focus();});
$('search').addEventListener('input',()=>{tablePages.clear();render();});
$('navigation-toggle').addEventListener('click',()=>{const open=$('navigation-toggle').getAttribute('aria-expanded')!=='true';setNavigationOpen(open);if(open)$('navigation').querySelector('.active')?.focus();});
$('show-latest').addEventListener('click',()=>{render();$('content').focus();});
window.addEventListener('popstate',event=>{const next=event.state?.view;if(knownViews.has(next))navigate(next,false);});
window.addEventListener('resize',()=>{for(const draw of cloudPlotRenderers)draw();});
document.addEventListener('keydown',event=>{
    if((event.ctrlKey||event.metaKey)&&event.key.toLowerCase()==='k'&&!['analysis','history','fleet','cloud'].includes(view)){event.preventDefault();$('search').focus();}
    if(event.key==='Escape'){
        if(document.body.classList.contains('navigation-open')){event.preventDefault();setNavigationOpen(false,true);return;}
        $('search').value='';render();
    }
});
$('language').addEventListener('change',()=>{lang=$('language').value;try{localStorage.setItem('opscope-language',lang);}catch{}translate();});
$('theme').addEventListener('click',()=>{const root=document.documentElement;root.dataset.theme=root.dataset.theme==='dark'?'light':'dark';try{localStorage.setItem('opscope-theme',root.dataset.theme);}catch{}});
$('full').addEventListener('change', async () => {
    const generation = ++privacyVersion;
    if (!$('full').checked) { snapshot = safeSnapshot; render(); }
    $('privacy').textContent = t($('full').checked ? 'fullWarning' : 'redacted');
    try { await refresh(); }
    catch (error) {
        if (generation !== privacyVersion) return;
        privacyVersion++;
        $('full').checked = false;
        snapshot = safeSnapshot;
        render();
        $('privacy').textContent = t('redacted');
        notice(error.message);
    }
});
$('collect').addEventListener('click',async()=>{collectionBusy=true;updateCollectionControl();$('collect').disabled=true;$('collect').querySelector('[data-i18n]').textContent=t('collecting');notice('');try{await json('/api/collect',{method:'POST'});await refresh();}catch(error){notice(error.message);}finally{collectionBusy=false;updateCollectionControl();}});
window.addEventListener('beforeunload',()=>{disposed=true;streamController?.abort();chartHandle?.dispose();window.OpscopeCharts?.reset();});
translate();
if(!token){notice(t('noToken'));$('collect').disabled=true;return;}
(async()=>{
    try{
        [settings,capabilities]=await Promise.all([json('/api/settings'),json('/api/capabilities')]);
        const catalog=await json('/api/cloud/catalog').catch(()=>null);
        if(catalog?.version===2&&Array.isArray(catalog.providers)&&Array.isArray(catalog.actions))cloudCatalog=catalog;
        if(capabilities.policy)policyResult=await json('/api/policy');
        await refresh();
        const history=await json('/api/metrics/history?window=30m&limit=720').catch(()=>null);
        const samples=Array.isArray(history)?history:Array.isArray(history?.samples)?history.samples:Array.isArray(history?.points)?history.points:[];
        for(const sample of samples){if(window.OpscopeCharts?.push(sample))lastMetricSequence=Math.max(lastMetricSequence,Number(sample.sequence)||0);}
        live();
    }catch(error){notice(error.message);setConnection('disconnected');}
})();
})();
