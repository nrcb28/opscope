'use strict';
// EN: Session tokens and evidence stay in memory; only language/theme preferences may persist.
// ES: Los tokens de sesión y la evidencia permanecen en memoria; solo se guardan idioma y tema.
(() => {
const $ = id => document.getElementById(id);
const token = new URLSearchParams(location.hash.slice(1)).get('token');
let authenticationMode = token ? 'local' : null;
const hasSession = () => authenticationMode === 'proxy' || authenticationMode === 'local' && !!token;
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
cloud:'Cloud & clusters', clusterAdapter:'Cluster adapter', infrastructureAdapter:'Infrastructure provider', clusterNote:'The Kubernetes context and namespaces are fixed when this session starts. Cluster evidence stays separate from infrastructure accounts.', clusterEvidence:'Cluster evidence', clusterUnlinked:'No infrastructure identity link has been verified. Similar names do not establish that a cluster belongs to a cloud resource.', clusterVerified:'Node references match the selected infrastructure inventory', clusterIdentityUnknown:'Cluster and control-plane identity remain unverified. A matching node reference does not prove ownership of the cluster.', clusterNodesObserved:'Observed nodes', clusterNodesMatched:'Matched node references', clusterNodesUnmatched:'Unmatched node references', clusterNode:'Node reference', clusterNamespaces:'Authorized namespaces', latestValue:'Latest observed value',
billingEvidence:'Observed billing-export rows', billingNote:'These are subtotals of the rows actually read from an existing billing export. They are not a complete bill or a forecast. Currencies are kept separate; missing rows never mean zero cost.', billingRowsRead:'Export rows read', billingMatchedRows:'Rows matching the authorized projects', billingCost:'Observed cost', billingCredits:'Observed credits', billingNetCost:'Observed net cost', currency:'Currency', billingNoRows:'No matching billing rows were observed. Cost is unknown.', billingPeriodStart:'Earliest observed usage', billingPeriodEnd:'Latest observed usage', sccEvidence:'Security Command Center observations', sccNote:'SCC findings reflect the configured project, permissions and collection window. An empty or unavailable response does not establish a secure project.', sccCount:'SCC observations', sccLocation:'SCC location', noAdvertisedOperations:'No web operations are advertised for this adapter.',
inventory:'Inventory', health:'Reported health', posture:'Configuration posture', metrics:'Metrics', cost:'Billing observations', patches:'Patch evidence', scc:'SCC findings', services:'Services', billingUnavailable:'Billing evidence is unavailable. Cost is unknown.',
cloudDrift:'Inventory baseline comparison', clusterNodeMatched:'Verified node reference', patchEvidence:'Existing OS Config job observations', patchNote:'These are existing patch-job observations, not a current compliance assessment. Job success does not prove that every VM is patched; missing, stale or unavailable observations remain unknown.', patchCompliance:'Current patch compliance', patchUnknown:'Unknown — no current compliance assessment', patchJobsRead:'Observed patch jobs', patchLatestUpdate:'Latest observed job update', patchFreshness:'Observation freshness window', patchJobState:'Observed job state', patchNoJobs:'No existing patch jobs were observed. Patch compliance remains unknown.', patchUnavailable:'Patch-job evidence is unavailable. Patch compliance remains unknown.', patchFresh:'Recent job observation', patchStale:'Stale job observation', patchCreated:'Job created', patchUpdated:'Job updated', patchInstances:'Observed instance count', patchSucceeded:'Instances reported succeeded', patchFailed:'Instances reported failed', patchDryRun:'Dry run', patchDryRunYes:'Yes — no patch execution', patchDryRunNo:'No',
cloudDriftEvidence:'Inventory baseline observations', cloudDriftNote:'This compares the configured saved inventory with the current inventory using only shared region and state fields. It is not a live infrastructure-as-code plan or a full configuration assessment.', cloudDriftBaseline:'Baseline observation', cloudDriftCurrent:'Current observation', cloudDriftCompared:'Resources compared', cloudDriftFields:'Shared fields compared', cloudDriftUnknown:'Unknown fields', cloudDriftAdded:'Added observations', cloudDriftMissing:'Missing observations', cloudDriftChanged:'Changed observations', cloudDriftAbsence:'Absence assessment', cloudDriftAbsenceYes:'Available for the matching complete scopes', cloudDriftAbsenceNo:'Unavailable — incomplete or non-comparable inventory', cloudDriftNoChanges:'No comparable changes were observed. Review coverage and unknown fields before drawing a conclusion.', cloudDriftUnavailable:'The inventory comparison is unavailable. Drift is unknown.', cloudDriftFieldNames:'Compared fields', cloudDriftAddedChange:'Added', cloudDriftMissingChange:'Missing', cloudDriftChangedChange:'Changed',
menu:'Sections', monitoringGroup:'Monitoring', hostGroup:'Host', investigationGroup:'Investigation', cloudGroup:'Cloud & clusters', outputGroup:'Output', systemGroup:'System',
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
cloud:'Nube y clústeres', clusterAdapter:'Adaptador de clúster', infrastructureAdapter:'Proveedor de infraestructura', clusterNote:'El contexto Kubernetes y los namespaces se fijan al iniciar esta sesión. Su evidencia se mantiene separada de las cuentas de infraestructura.', clusterEvidence:'Evidencia del clúster', clusterUnlinked:'No se ha verificado un vínculo de identidad con la infraestructura. Los nombres parecidos no demuestran que el clúster pertenezca a un recurso cloud.', clusterVerified:'Referencias de nodos coincidentes con el inventario de infraestructura seleccionado', clusterIdentityUnknown:'La identidad del clúster y del plano de control sigue sin verificar. Una referencia de nodo coincidente no demuestra la propiedad del clúster.', clusterNodesObserved:'Nodos observados', clusterNodesMatched:'Referencias de nodos coincidentes', clusterNodesUnmatched:'Referencias de nodos sin coincidencia', clusterNode:'Referencia de nodo', clusterNamespaces:'Namespaces autorizados', latestValue:'Último valor observado',
billingEvidence:'Filas observadas de la exportación de facturación', billingNote:'Son subtotales de las filas que se han leído de una exportación existente. No representan una factura completa ni una previsión. Las monedas se conservan separadas; la ausencia de filas no equivale a coste cero.', billingRowsRead:'Filas de exportación leídas', billingMatchedRows:'Filas de los proyectos autorizados', billingCost:'Coste observado', billingCredits:'Créditos observados', billingNetCost:'Coste neto observado', currency:'Moneda', billingNoRows:'No se observaron filas de facturación coincidentes. Se desconoce el coste.', billingPeriodStart:'Primer uso observado', billingPeriodEnd:'Último uso observado', sccEvidence:'Observaciones de Security Command Center', sccNote:'Los hallazgos SCC reflejan el proyecto, permisos y ventana configurados. Una respuesta vacía o no disponible no demuestra que el proyecto sea seguro.', sccCount:'Observaciones SCC', sccLocation:'Ubicación SCC', noAdvertisedOperations:'El adaptador no anuncia operaciones web.',
inventory:'Inventario', health:'Salud declarada', posture:'Configuración de seguridad', metrics:'Métricas', cost:'Observaciones de facturación', patches:'Evidencia de parches', scc:'Hallazgos SCC', services:'Servicios', billingUnavailable:'La evidencia de facturación no está disponible. Se desconoce el coste.',
cloudDrift:'Comparación del inventario con línea base', clusterNodeMatched:'Referencia de nodo verificada', patchEvidence:'Observaciones de jobs existentes de OS Config', patchNote:'Son observaciones de jobs de parches existentes, no una evaluación de cumplimiento actual. El éxito de un job no demuestra que todas las VM estén parcheadas; las observaciones ausentes, obsoletas o no disponibles siguen siendo desconocidas.', patchCompliance:'Cumplimiento de parches actual', patchUnknown:'Desconocido — sin evaluación actual de cumplimiento', patchJobsRead:'Jobs de parches observados', patchLatestUpdate:'Última actualización de job observada', patchFreshness:'Ventana de frescura de la observación', patchJobState:'Estado observado del job', patchNoJobs:'No se observaron jobs de parches existentes. Se desconoce el cumplimiento.', patchUnavailable:'La evidencia de jobs no está disponible. Se desconoce el cumplimiento de parches.', patchFresh:'Observación reciente del job', patchStale:'Observación obsoleta del job', patchCreated:'Creación del job', patchUpdated:'Actualización del job', patchInstances:'Instancias observadas', patchSucceeded:'Instancias con éxito declarado', patchFailed:'Instancias con fallo declarado', patchDryRun:'Simulación', patchDryRunYes:'Sí — sin ejecutar parches', patchDryRunNo:'No',
cloudDriftEvidence:'Observaciones de la línea base de inventario', cloudDriftNote:'Compara el inventario guardado configurado con el actual usando solo los campos compartidos de región y estado. No es un plan de infraestructura como código en vivo ni una evaluación completa de configuración.', cloudDriftBaseline:'Observación de la línea base', cloudDriftCurrent:'Observación actual', cloudDriftCompared:'Recursos comparados', cloudDriftFields:'Campos compartidos comparados', cloudDriftUnknown:'Campos desconocidos', cloudDriftAdded:'Observaciones añadidas', cloudDriftMissing:'Observaciones ausentes', cloudDriftChanged:'Observaciones cambiadas', cloudDriftAbsence:'Evaluación de ausencias', cloudDriftAbsenceYes:'Disponible para ámbitos completos coincidentes', cloudDriftAbsenceNo:'No disponible — inventario incompleto o no comparable', cloudDriftNoChanges:'No se observaron cambios comparables. Revisa la cobertura y los campos desconocidos antes de sacar conclusiones.', cloudDriftUnavailable:'La comparación de inventario no está disponible. Se desconoce el drift.', cloudDriftFieldNames:'Campos comparados', cloudDriftAddedChange:'Añadido', cloudDriftMissingChange:'Ausente', cloudDriftChangedChange:'Cambiado',
menu:'Secciones', monitoringGroup:'Supervisión', hostGroup:'Host', investigationGroup:'Investigación', cloudGroup:'Nube y clústeres', outputGroup:'Salida', systemGroup:'Sistema',
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
let cloudReadMetadata = null, cloudGateUntil = 0;
const cloudScopeCooldowns = new Map();
let analysisExportFormat = 'json', policyBusy = false, collectionBusy = false, cooldownUntil = 0, snapshotVersion = 0;
const tablePages = new Map(), tableSizes = new Map(), tableSorts = new Map();
Object.assign(words.en, {
networks:'Regional networks', configurationEvidence:'Observed configuration', configurationNote:'These are observed configuration fields and counts. Missing or unavailable fields remain unknown. They do not establish effective reachability, application availability or complete security posture.', configurationProjection:'Allowed configuration fields', configurationProjectionNote:'Configuration evidence below is limited to the fields supported by this view.', configurationUnavailable:'This read is unavailable. Its configuration values are unknown.', configurationNoChecks:'No supported configuration observations were returned.', configurationTls:'TLS settings', configurationDns:'DNS metadata', configurationWaf:'WAF metadata', configurationRoutes:'Worker route metadata', configurationDisks:'Disk encryption observations', configurationGroups:'Security-group observations', configurationVpcs:'Regional VPC observations', configurationPrivateNetworks:'Regional private-network observations', configurationSsl:'Observed SSL mode', configurationMinimumTls:'Minimum TLS version', configurationHttps:'Always use HTTPS', configurationEnabled:'Enabled', configurationDisabled:'Disabled', configurationRecords:'Observed DNS records', configurationProxied:'Observed proxied records', configurationUnproxied:'Observed unproxied records', configurationProxyUnknown:'Records with unknown proxy state', configurationRecordTypes:'Observed record types', configurationRecordType:'DNS record type', configurationRulesets:'Observed rulesets', configurationPhases:'Observed rule phases', configurationRules:'Observed rules', configurationEnabledRules:'Observed enabled rules', configurationDisabledRules:'Observed disabled rules', configurationUnknownRules:'Rules with unknown state', configurationRoutesRead:'Observed routes', configurationDisksRead:'Observed disks', configurationUnencrypted:'Observed unencrypted disks', configurationEncryptionUnknown:'Disks with unknown encryption', configurationGroupsRead:'Observed security groups', configurationWorldIngress:'Observed global ingress allow rules', configurationAdminIngress:'Observed administrative ingress allow rules', configurationShadowed:'Possibly shadowed administrative allow rules', configurationResources:'Observed regional resources', configurationExpected:'Provider-declared resources'
});
Object.assign(words.es, {
networks:'Redes regionales', configurationEvidence:'Configuración observada', configurationNote:'Son campos y recuentos de configuración observados. Los campos ausentes o no disponibles siguen siendo desconocidos. No demuestran accesibilidad efectiva, disponibilidad de aplicación ni una evaluación completa de seguridad.', configurationProjection:'Campos de configuración admitidos', configurationProjectionNote:'La evidencia de configuración se limita a los campos admitidos por esta vista.', configurationUnavailable:'La lectura no está disponible. Se desconocen sus valores de configuración.', configurationNoChecks:'No se recibieron observaciones de configuración compatibles.', configurationTls:'Configuración TLS', configurationDns:'Metadatos DNS', configurationWaf:'Metadatos WAF', configurationRoutes:'Metadatos de rutas Worker', configurationDisks:'Observaciones de cifrado de discos', configurationGroups:'Observaciones de security groups', configurationVpcs:'Observaciones de VPC regionales', configurationPrivateNetworks:'Observaciones de redes privadas regionales', configurationSsl:'Modo SSL observado', configurationMinimumTls:'Versión TLS mínima', configurationHttps:'Usar HTTPS siempre', configurationEnabled:'Activado', configurationDisabled:'Desactivado', configurationRecords:'Registros DNS observados', configurationProxied:'Registros observados con proxy', configurationUnproxied:'Registros observados sin proxy', configurationProxyUnknown:'Registros con estado de proxy desconocido', configurationRecordTypes:'Tipos de registro observados', configurationRecordType:'Tipo de registro DNS', configurationRulesets:'Rulesets observados', configurationPhases:'Fases de reglas observadas', configurationRules:'Reglas observadas', configurationEnabledRules:'Reglas activadas observadas', configurationDisabledRules:'Reglas desactivadas observadas', configurationUnknownRules:'Reglas con estado desconocido', configurationRoutesRead:'Rutas observadas', configurationDisksRead:'Discos observados', configurationUnencrypted:'Discos sin cifrar observados', configurationEncryptionUnknown:'Discos con cifrado desconocido', configurationGroupsRead:'Security groups observados', configurationWorldIngress:'Reglas allow de entrada global observadas', configurationAdminIngress:'Reglas allow de entrada administrativa observadas', configurationShadowed:'Reglas allow administrativas posiblemente anuladas', configurationResources:'Recursos regionales observados', configurationExpected:'Recursos declarados por el proveedor'
});
const knownProviders = new Set(['azure','aws','gcp','oci','digitalocean','hetzner','cloudflare','openstack','alibaba','ibm','scaleway','kubernetes']);
Object.assign(words.en, {
configurationProjectResources:'Project membership observations', configurationDroplets:'Project droplet observations', configurationVolumes:'Project volume observations', configurationLoadBalancers:'Project load-balancer observations', configurationFirewalls:'Related firewall observations', configurationObservedResources:'Observed resources', digitalOceanEvidence:'Project resource relationships', digitalOceanScope:'Selected project scope', digitalOceanScopeVerified:'Verified by the Projects API read', digitalOceanScopeNote:'The read covers visible resources in the selected project. Project verification does not establish a team or account identity.', digitalOceanVpcNote:'VPC observations describe references from selected project resources. They do not prove exclusive project ownership, isolation or reachability.', digitalOceanFirewallNote:'Direct or tag membership links the observed firewall to selected droplets. Tags and rule contents are omitted; configured ingress does not prove an effective network path.', runEvidence:'Cloud Run service configuration', runNote:'Ingress and Ready state are observed configuration and status, not proof of application availability. This Cloud Run v1 source does not provide the service last-update time; it remains unknown.', runState:'Observed Ready state', runIngress:'Ingress configuration', runLastUpdated:'Last update', runReadyRevision:'Ready revision observed', runRevisionPresent:'Observed', runRevisionMissing:'Not observed'
});
Object.assign(words.es, {
configurationProjectResources:'Observaciones de pertenencia al proyecto', configurationDroplets:'Observaciones de droplets del proyecto', configurationVolumes:'Observaciones de volúmenes del proyecto', configurationLoadBalancers:'Observaciones de balanceadores del proyecto', configurationFirewalls:'Observaciones de firewalls relacionados', configurationObservedResources:'Recursos observados', digitalOceanEvidence:'Relaciones de recursos del proyecto', digitalOceanScope:'Ámbito del proyecto seleccionado', digitalOceanScopeVerified:'Verificado por la lectura de la API de Projects', digitalOceanScopeNote:'La lectura abarca los recursos visibles del proyecto seleccionado. Verificar el proyecto no establece la identidad de un equipo o cuenta.', digitalOceanVpcNote:'Las observaciones VPC describen referencias desde recursos del proyecto seleccionado. No demuestran propiedad exclusiva del proyecto, aislamiento ni accesibilidad.', digitalOceanFirewallNote:'La pertenencia directa o mediante tags vincula el firewall observado con los droplets seleccionados. Los tags y el contenido de las reglas se omiten; la configuración de entrada no demuestra una ruta de red efectiva.', runEvidence:'Configuración de servicios Cloud Run', runNote:'Ingress y Ready son configuración y estado observados, no una prueba de disponibilidad de aplicación. Esta fuente Cloud Run v1 no proporciona la fecha de última actualización del servicio; permanece desconocida.', runState:'Estado Ready observado', runIngress:'Configuración de ingress', runLastUpdated:'Última actualización', runReadyRevision:'Revisión Ready observada', runRevisionPresent:'Observada', runRevisionMissing:'No observada'
});
Object.assign(words.en, {configurationExpectedResources:'Expected resources',digitalOceanCountsNote:'Expected counts follow visible project membership or selected resource references. Missing totals remain unknown; an account-wide firewall count does not establish a project total.'});
Object.assign(words.es, {configurationExpectedResources:'Recursos esperados',digitalOceanCountsNote:'Los recuentos esperados siguen la pertenencia visible al proyecto o las referencias de recursos seleccionados. Los totales ausentes siguen siendo desconocidos; un recuento de firewalls de la cuenta no establece un total del proyecto.'});
Object.assign(words.en, {
configurationSubnets:'Regional subnet observations', configurationScopeVerification:'Account and resource-group scope', configurationScopeVerified:'Verified by the resource-manager read', configurationScopeUnknown:'Unknown / unverified', nodePoolEvidence:'GKE node-pool configuration', nodePoolNote:'Each observation belongs to the cluster shown. Initial counts and autoscaling bounds describe configuration, not current or desired node counts. Management flags do not establish node health. This metadata does not verify Kubernetes cluster or control-plane identity.', nodePoolCluster:'Parent cluster', nodePoolObserved:'Observed node pools', nodePoolReturned:'Provider-returned node-pool rows', nodePoolUnavailable:'Node-pool configuration is unavailable. Its values remain unknown.', nodePoolEmpty:'No node pools were observed in this complete cluster read.', nodePoolState:'Observed pool state', nodePoolVersion:'Configured node version', nodePoolInitial:'Configured initial node count', nodePoolAutoscaling:'Autoscaling enabled', nodePoolMin:'Configured minimum nodes per zone', nodePoolMax:'Configured maximum nodes per zone', nodePoolTotalMin:'Configured total minimum nodes', nodePoolTotalMax:'Configured total maximum nodes', nodePoolPolicy:'Configured location policy', nodePoolRepair:'Automatic repair configured', nodePoolUpgrade:'Automatic upgrade configured', nodePoolProjection:'Allowed service metadata', nodePoolProjectionNote:'Only supported service metadata fields are shown. Missing or invalid values remain unknown.'
});
Object.assign(words.es, {
configurationSubnets:'Observaciones de subredes regionales', configurationScopeVerification:'Ámbito de cuenta y grupo de recursos', configurationScopeVerified:'Verificado por la lectura de Resource Manager', configurationScopeUnknown:'Desconocido / sin verificar', nodePoolEvidence:'Configuración de pools de nodos GKE', nodePoolNote:'Cada observación pertenece al clúster indicado. Los recuentos iniciales y límites de autoescalado describen configuración, no el número actual ni deseado de nodos. Los indicadores de gestión no demuestran la salud de los nodos. Estos metadatos no verifican la identidad del clúster Kubernetes ni del plano de control.', nodePoolCluster:'Clúster padre', nodePoolObserved:'Pools de nodos observados', nodePoolReturned:'Filas de pools devueltas por el proveedor', nodePoolUnavailable:'La configuración de pools de nodos no está disponible. Sus valores siguen siendo desconocidos.', nodePoolEmpty:'No se observaron pools de nodos en esta lectura completa del clúster.', nodePoolState:'Estado observado del pool', nodePoolVersion:'Versión de nodos configurada', nodePoolInitial:'Recuento inicial de nodos configurado', nodePoolAutoscaling:'Autoescalado activado', nodePoolMin:'Mínimo de nodos configurado por zona', nodePoolMax:'Máximo de nodos configurado por zona', nodePoolTotalMin:'Mínimo total de nodos configurado', nodePoolTotalMax:'Máximo total de nodos configurado', nodePoolPolicy:'Política de ubicación configurada', nodePoolRepair:'Reparación automática configurada', nodePoolUpgrade:'Actualización automática configurada', nodePoolProjection:'Metadatos de servicios admitidos', nodePoolProjectionNote:'Solo se muestran los campos de metadatos admitidos. Los valores ausentes o inválidos siguen siendo desconocidos.'
});
Object.assign(words.en, {
connections:'Connections', connectionsDescription:'Connect authorized cloud accounts from the host running Opscope.', connectionsNote:'Creating an account, signing in and granting read access are separate steps. This guide checks host setup without signing in or contacting a provider. Credentials stay on the Opscope host.', connectionsUnavailable:'Connection guidance could not be loaded. Retry while the Opscope session is active.', refreshConnections:'Refresh setup checks', connectionSetup:'Host setup', connectionGuide:'Set up this provider', connectionScope:'Read scope', connectionCredential:'Credential setup', connectionTool:'Provider tool', connectionAccess:'Last provider read', connectionScopeReady:'Scope configured · access unverified', connectionScopeMissing:'No read scope configured', connectionPresent:'Present · authentication unverified', connectionExternal:'External session · unverified', connectionMissing:'Missing', connectionUnavailable:'Could not check', connectionAvailable:'Available · session unverified', connectionUntrusted:'Untrusted executable', connectionNotRequired:'Not required', connectionNotTested:'Access not tested', connectionSucceeded:'Last read succeeded · review its scope and time', connectionPartial:'Last read returned partial evidence', connectionNoData:'Last read returned no observations', connectionDenied:'Last read denied', connectionRateLimited:'Last read rate limited', connectionTimedOut:'Last read timed out', connectionFailed:'Last read failed', connectionNotConfigured:'Last read needs configuration', connectionUnsupported:'Read unsupported', connectionRequirements:'Operation-specific requirements', connectionSteps:'Steps on the Opscope host', connectionSignup:'Create an account', connectionConsole:'Open provider console', connectionDocs:'Official setup documentation', connectionTest:'Test read access', connectionTestNote:'Runs an existing configured read. Setup presence does not establish authentication or access.', connectionNoTest:'Configure an explicit authorized read scope to enable an access test.', connectionObserved:'Setup checked', connectionHelp:'Open Connections to review account setup and permissions.', proxy_local:'HOSTED', proxy_connected:'Authenticated hosted session', proxy_redacted:'Identifiers redacted · No telemetry · Authenticated proxy', proxy_footer:'Evidence stays on the Opscope host.', proxy_errorAuth:'The hosted session is no longer authorized. Sign in through your configured proxy again.'
});
Object.assign(words.es, {
connections:'Conexiones', connectionsDescription:'Conecta tus cuentas cloud desde el host donde se ejecuta Opscope.', connectionsNote:'Crear una cuenta, iniciar sesión y conceder acceso de lectura son pasos distintos. Esta guía comprueba la preparación del host sin iniciar sesión ni consultar al proveedor. Las credenciales permanecen en el host de Opscope.', connectionsUnavailable:'No se pudo cargar la guía de conexión. Reintenta con la sesión de Opscope activa.', refreshConnections:'Actualizar comprobaciones', connectionSetup:'Preparación del host', connectionGuide:'Configurar este proveedor', connectionScope:'Ámbito de lectura', connectionCredential:'Credenciales', connectionTool:'Herramienta del proveedor', connectionAccess:'Última lectura del proveedor', connectionScopeReady:'Ámbito configurado · acceso sin verificar', connectionScopeMissing:'Sin ámbito de lectura configurado', connectionPresent:'Presente · autenticación sin verificar', connectionExternal:'Sesión externa · sin verificar', connectionMissing:'Ausente', connectionUnavailable:'No se pudo comprobar', connectionAvailable:'Disponible · sesión sin verificar', connectionUntrusted:'Ejecutable no confiable', connectionNotRequired:'No necesaria', connectionNotTested:'Acceso sin probar', connectionSucceeded:'Última lectura correcta · revisa su ámbito y fecha', connectionPartial:'Última lectura con evidencia parcial', connectionNoData:'Última lectura sin observaciones', connectionDenied:'Última lectura denegada', connectionRateLimited:'Última lectura limitada por cuota', connectionTimedOut:'Última lectura agotó el tiempo', connectionFailed:'Última lectura fallida', connectionNotConfigured:'Última lectura necesita configuración', connectionUnsupported:'Lectura no implementada', connectionRequirements:'Requisitos por operación', connectionSteps:'Pasos en el host de Opscope', connectionSignup:'Crear una cuenta', connectionConsole:'Abrir consola del proveedor', connectionDocs:'Documentación oficial', connectionTest:'Probar acceso de lectura', connectionTestNote:'Ejecuta una lectura ya configurada. La presencia de configuración no demuestra autenticación ni permisos.', connectionNoTest:'Configura un ámbito de lectura autorizado para habilitar una prueba de acceso.', connectionObserved:'Preparación comprobada', connectionHelp:'Abre Conexiones para revisar la cuenta y sus permisos.', proxy_local:'ALOJADA', proxy_connected:'Sesión alojada autenticada', proxy_redacted:'Identificadores redactados · Sin telemetría · Proxy autenticado', proxy_footer:'La evidencia permanece en el host de Opscope.', proxy_errorAuth:'La sesión alojada ya no está autorizada. Vuelve a iniciar sesión en el proxy configurado.'
});
const knownOperations = new Set(['inventory','health','posture','metrics','cost','patches','drift','scc','services','networks']);
const knownViews = new Set(['overview','findings','processes','services','analysis','drift','fleet','history','cloud','connections','policy','reports','settings']);
Object.assign(words.en, {cloudCached:'Retained result · no new provider read', cloudFresh:'New action result', cloudCacheNote:'The result keeps its original observation time. A repeated request may reuse the session cache.', cloudCacheStored:'Stored in this session', cloudCacheExpires:'Cache expiry', cloudCacheAge:'Cache age', cloudCacheRemaining:'Cache reuse remaining', cloudRetry:'This configured scope is cooling down.', cloudRetryNote:'Retry manually after the countdown. Host collection and other cloud scopes remain available.'});
Object.assign(words.es, {cloudCached:'Resultado conservado · sin nueva lectura del proveedor', cloudFresh:'Nuevo resultado de la acción', cloudCacheNote:'El resultado conserva su hora de observación original. Una solicitud repetida puede reutilizar la caché de sesión.', cloudCacheStored:'Guardado en esta sesión', cloudCacheExpires:'Caducidad de la caché', cloudCacheAge:'Edad de la caché', cloudCacheRemaining:'Reutilización restante de caché', cloudRetry:'Este ámbito configurado está en espera.', cloudRetryNote:'Reintenta manualmente al terminar la cuenta atrás. La recopilación del host y otros ámbitos cloud siguen disponibles.'});
let cloudConnections = null, connectionsError = null, connectionsBusy = false, connectionProvider = 'all';
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
const t = key => words[lang][authenticationMode === 'proxy' && ['local','connected','redacted','footer','errorAuth'].includes(key) ? 'proxy_'+key : key] || words[lang][key] || key;
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
        const headers = new Headers(options.headers);
        if(authenticationMode === 'proxy') headers.delete('X-Opscope-Token');
        else headers.set('X-Opscope-Token', token || '');
        response=await fetch(path,{...options,signal:controller?.signal || options.signal,headers,credentials:authenticationMode === 'proxy'?'same-origin':'omit',cache:'no-store',referrerPolicy:'no-referrer'});
    } catch(error) {
        if(options.signal?.aborted)throw error;
        throw new Error(t(timedOut?'requestTimeout':'errorUnavailable'));
    } finally {clearTimeout(timeout);options.signal?.removeEventListener('abort',forwardAbort);}
    const cloudRequest = cloudActionForRequest(path, options.method);
    const cloudMetadata = cloudRequest ? readCloudMetadata(response) : null;
    const scopedRetry = cloudRequest ? recordCloudRetry(response, cloudRequest) : false;
    if (response.ok) { response.cloudReadMetadata = cloudMetadata; return response; }
    let message = response.status === 429 ? t('busy') : response.status === 401 || response.status === 403 ? t('errorAuth') : response.status === 400 || response.status === 413 ? t('errorInvalid') : response.status === 504 ? t('requestTimeout') : response.status >= 500 ? t('errorUnavailable') : t('error'), failureReport = null;
    if (response.status === 401 || response.status === 403) setConnection('disconnected');
    let problemCode = null;
    if (['/api/policy/preview', '/api/fleet', '/api/analyze', '/api/report'].includes(path) || path.startsWith('/api/cloud/')) {
        try {
            const problem = await response.json();
            problemCode = problem.cloudProblem?.code || problem.code;
            if (typeof problem.kind === 'string' && Array.isArray(problem.findings) && Array.isArray(problem.warnings)) failureReport = problem;
            message = [problem.error, problem.detail].filter(value => typeof value === 'string').join(' ') || message;
            if(path.startsWith('/api/cloud/') && problem.cloudProblem && typeof problem.cloudProblem === 'object')
                message = [problem.cloudProblem.message, problem.cloudProblem.remediation].filter(value => typeof value === 'string' && value.length <= 1000).join(' ') || message;
        } catch {}
    }
    if (response.status === 429) {
        const seconds = retryDelaySeconds(response);
        const providerRetry = cloudRequest && problemCode === 'PROVIDER_RATE_LIMITED';
        if (providerRetry && !scopedRetry) setCloudRetry(cloudRequest.scopeAlias, seconds);
        if (!scopedRetry && !providerRetry) cooldownUntil = Math.max(cooldownUntil, Date.now() + seconds * 1000);
        message += ` ${t('retryIn')} ${seconds} ${t('seconds')}.`;
        updateCollectionControl();
    }
    const error = new Error(message);
    error.status = response.status;
    error.report = failureReport;
    error.cloudReadMetadata = cloudMetadata;
    throw error;
}
function updateCollectionControl() {
    const control = $('collect'), remaining = Math.max(0, Math.ceil((cooldownUntil - Date.now()) / 1000));
    control.disabled = !hasSession() || collectionBusy || remaining > 0;
    control.querySelector('[data-i18n]').textContent = collectionBusy ? t('collecting') : remaining ? `${t('retryIn')} ${remaining}s` : t('collect');
    control.title = remaining ? `${t('retryIn')} ${remaining} ${t('seconds')}` : '';
    updateCloudControls();
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
    if (['analysis','history','fleet','cloud','connections'].includes(view) && $('full').checked) {
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
    const saved = ['analysis','history','fleet','cloud','connections'].includes(view);
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
        if ($('full').checked && !['analysis','history','fleet','cloud','connections'].includes(view)) { notice(t('fullTableExport')); return; }
        const csv = [headers.map(t),...sortedRows()].map(row => row.map(csvValue).join(',')).join('\r\n');
        saveBlob(new Blob(['\uFEFF'+csv],{type:'text/csv;charset=utf-8'}),`opscope-${view}-redacted.csv`);
    });
    exportButton.disabled = $('full').checked && !['analysis','history','fleet','cloud','connections'].includes(view);
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
                if ($('full').checked && !['analysis','history','fleet','cloud','connections'].includes(view)) return;
                try { await navigator.clipboard.writeText(JSON.stringify(finding,null,2)); notice(t('copied')); } catch { notice(t('copyFailed')); }
            });
            copy.disabled = $('full').checked && !['analysis','history','fleet','cloud','connections'].includes(view);
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
        if (cloudCatalog) {
            const descriptor = cloudCatalog.providers?.find(provider => provider.id === action.providerId);
            const capability = descriptor?.operations?.find(operation => operation.name === action.operation);
            if (!capability || capability.supported !== true || capability.readOnly !== true || capability.availability !== 'configured') return false;
        }
        const parts=action.actionKey.split('/');
        return parts.length===2 && parts[1]===action.operation && parts[0]===action.scopeAlias && new RegExp('^'+action.providerId+'(?:-scope-[1-9][0-9]*)?$').test(action.scopeAlias);
    });
}
function providerDescriptors() {
    const names={azure:'Microsoft Azure',aws:'Amazon Web Services',gcp:'Google Cloud',oci:'Oracle Cloud',digitalocean:'DigitalOcean',hetzner:'Hetzner Cloud',cloudflare:'Cloudflare',openstack:'OpenStack',alibaba:'Alibaba Cloud',ibm:'IBM Cloud',scaleway:'Scaleway',kubernetes:'Kubernetes'};
    return [...knownProviders].map(id=>{
        const descriptor=cloudCatalog?.providers?.find(item=>item.id===id);
        const operations=Array.isArray(descriptor?.operations)?descriptor.operations.filter(item=>item&&knownOperations.has(item.name)&&item.supported===true&&item.readOnly===true):[];
        return {id,displayName:typeof descriptor?.displayName==='string'?descriptor.displayName:names[id],category:id==='kubernetes'?'cluster':descriptor?.category || '',operations};
    });
}
function cloudActionForRequest(path, method) {
    if (String(method || 'GET').toUpperCase() !== 'POST') return null;
    return validatedCloudActions().find(action => path === `/api/cloud/${action.scopeAlias}/${action.operation}`) || null;
}
function retryDelaySeconds(response) {
    const retry = response.headers.get('Retry-After');
    const delay = /^\d{1,10}$/.test(retry || '') ? Number(retry) : Math.ceil((Date.parse(retry) - Date.now()) / 1000);
    return Number.isFinite(delay) && delay > 0 ? Math.min(delay, 3600) : 2;
}
function setCloudRetry(scopeAlias, seconds) {
    if (!validatedCloudActions().some(action => action.scopeAlias === scopeAlias) || !Number.isFinite(seconds) || seconds <= 0) return;
    cloudScopeCooldowns.set(scopeAlias, Math.max(cloudScopeCooldowns.get(scopeAlias) || 0, performance.now() + Math.min(seconds, 3600) * 1000));
}
function recordCloudRetry(response, action) {
    const scope = response.headers.get('X-Opscope-Retry-Scope'), reason = response.headers.get('X-Opscope-Retry-Reason');
    if (scope !== action.scopeAlias || !['provider-quota', 'scope-cooldown', 'workspace-busy'].includes(reason) || !response.headers.has('Retry-After')) return false;
    const seconds = retryDelaySeconds(response);
    if (reason === 'workspace-busy') cloudGateUntil = Math.max(cloudGateUntil, performance.now() + seconds * 1000);
    else setCloudRetry(scope, seconds);
    return true;
}
function cloudWaitSeconds(action) {
    return Math.max(0, Math.ceil(Math.max((cloudScopeCooldowns.get(action.scopeAlias) || 0) - performance.now(), cloudGateUntil - performance.now(), cooldownUntil - Date.now()) / 1000));
}
function configureCloudButton(control, action, mode = 'query') {
    control.dataset.cloudAction = action.actionKey;
    control.dataset.cloudMode = mode;
    return control;
}
function updateCloudControls() {
    for (const control of document.querySelectorAll('button[data-cloud-action]')) {
        const action = validatedCloudActions().find(item => item.actionKey === control.dataset.cloudAction);
        if (!action) { control.disabled = true; continue; }
        const remaining = cloudWaitSeconds(action), base = `${t(control.dataset.cloudMode === 'test' ? 'connectionTest' : 'run')} · ${action.actionKey}`;
        control.disabled = cloudBusy || remaining > 0;
        control.textContent = base + (remaining ? ` · ${t('retryIn')} ${remaining}s` : '');
        control.title = remaining ? `${t('cloudRetry')} ${t('cloudRetryNote')}` : '';
    }
    if (cloudReadMetadata) {
        const elapsed = Math.max(0, Math.floor((performance.now() - cloudReadMetadata.receivedAt) / 1000));
        const age = document.querySelector('[data-cloud-cache-age]'), remaining = document.querySelector('[data-cloud-cache-remaining]');
        if (age) age.textContent = cloudReadMetadata.ageSeconds === null ? t('unknown') : `${cloudReadMetadata.ageSeconds + elapsed} s`;
        if (remaining) remaining.textContent = cloudReadMetadata.remainingSeconds === null ? t('unknown') : `${Math.max(0, cloudReadMetadata.remainingSeconds - elapsed)} s`;
    }
}
function readCloudMetadata(response) {
    const cache = response.headers.get('X-Opscope-Cache');
    if (!['hit', 'miss'].includes(cache)) return null;
    const integer = name => { const value = response.headers.get(name); return /^\d{1,8}$/.test(value || '') && Number(value) <= 3600 ? Number(value) : null; };
    const instant = name => { const value = response.headers.get(name); return typeof value === 'string' && value.length <= 64 && Number.isFinite(Date.parse(value)) ? value : null; };
    return { cache, ageSeconds: integer('X-Opscope-Cache-Age-Seconds'), remainingSeconds: integer('X-Opscope-Cache-Remaining-Seconds'), cachedAtUtc: instant('X-Opscope-Cache-Cached-At'), expiresAtUtc: instant('X-Opscope-Cache-Expires-At'), receivedAt: performance.now() };
}
function syncCloudCoverage(coverage) {
    if (coverage?.schemaVersion !== 1 || !Array.isArray(coverage.actions) || coverage.actions.length > 512) return;
    for (const observation of coverage.actions) {
        const action = validatedCloudActions().find(item => item.actionKey === observation?.actionKey);
        if (!action || observation.canRequestRead !== false || !['provider-quota', 'scope-cooldown'].includes(observation.retryReason)) continue;
        if (Number.isSafeInteger(observation.retryAfterSeconds)) setCloudRetry(action.scopeAlias, observation.retryAfterSeconds);
    }
}
async function runCloudQuery(action) {
    if(cloudBusy || cloudWaitSeconds(action) || !validatedCloudActions().some(item=>item.actionKey===action.actionKey))return;
    const version=++cloudVersion; cloudAction=action.actionKey;cloudBusy=true;cloudError=null;cloudResult=null;cloudReadMetadata=null;notice('');render();
    try {const response=await api(`/api/cloud/${action.scopeAlias}/${action.operation}`,{method:'POST'}), result=await response.json();if(version===cloudVersion){cloudResult=result;cloudReadMetadata=response.cloudReadMetadata;}}
    catch(error){if(version===cloudVersion){cloudError=`${t('cloudFailed')} ${error.status===504?t('cloudTimeout'):error.status===424?t('cloudDenied')+' '+error.message:error.message}`;cloudResult=error.report||null;cloudReadMetadata=error.cloudReadMetadata;}}
    finally{if(version===cloudVersion){cloudBusy=false;render();loadConnections(false).then(()=>{if(view==='connections')render();});}}
}
const connectionHosts = {
    azure:['azure.microsoft.com','portal.azure.com','learn.microsoft.com'],aws:['portal.aws.amazon.com','console.aws.amazon.com','docs.aws.amazon.com'],gcp:['cloud.google.com','console.cloud.google.com'],oci:['signup.cloud.oracle.com','cloud.oracle.com','docs.oracle.com'],digitalocean:['cloud.digitalocean.com','docs.digitalocean.com'],hetzner:['accounts.hetzner.com','console.hetzner.cloud','docs.hetzner.cloud'],cloudflare:['dash.cloudflare.com','developers.cloudflare.com'],openstack:['docs.openstack.org'],alibaba:['account.alibabacloud.com','home.console.aliyun.com','www.alibabacloud.com'],ibm:['cloud.ibm.com'],scaleway:['console.scaleway.com','www.scaleway.com'],kubernetes:['kubernetes.io']
};
const connectionStateLabels = {'external-unverified':'connectionExternal',missing:'connectionMissing',present:'connectionPresent',unavailable:'connectionUnavailable',unknown:'unknown',available:'connectionAvailable',untrusted:'connectionUntrusted','not-required':'connectionNotRequired','not-tested':'connectionNotTested','last-read-succeeded':'connectionSucceeded',partial:'connectionPartial','no-data':'connectionNoData','permission-denied':'connectionDenied','rate-limited':'connectionRateLimited','timed-out':'connectionTimedOut',failed:'connectionFailed','not-configured':'connectionNotConfigured',unsupported:'connectionUnsupported'};
const connectionRequirementNames = new Set(['az','aws','gcloud','oci','openstack','aliyun','kubectl','DIGITALOCEAN_ACCESS_TOKEN','HCLOUD_TOKEN','CLOUDFLARE_API_TOKEN','IBM_CLOUD_IAM_TOKEN','SCW_SECRET_KEY','SCW_COCKPIT_TOKEN','cli-session','cli-session-and-adc','kubeconfig','Application Default Credentials']);
const safeConnectionText = (value, limit=1500) => typeof value === 'string' && value.length <= limit ? value : '';
function connectionLink(providerId, value, label) {
    if(typeof value !== 'string' || value.length>1024)return null;
    try {
        const url=new URL(value);
        if(url.protocol!=='https:'||url.username||url.password||url.port||!connectionHosts[providerId]?.includes(url.hostname))return null;
        const link=el('a',t(label));link.href=url.href;link.target='_blank';link.rel='noopener noreferrer';return link;
    } catch{return null;}
}
async function loadConnections(showBusy=true) {
    if(showBusy){connectionsBusy=true;connectionsError=null;render();}
    try {
        const result=await json('/api/cloud/connections');
        if(result?.version!==1||result.mode!=='guided-setup'||result.authenticationActionsAvailable!==false||result.remoteRequestsMade!==false||!Array.isArray(result.providers))throw new Error(t('connectionsUnavailable'));
        cloudConnections=result;connectionsError=null;
        syncCloudCoverage(await json('/api/cloud/coverage').catch(()=>null));
    } catch(error){connectionsError=error.message;}
    finally {if(showBusy){connectionsBusy=false;render();}}
}
function showConnections() {
    const wrap=panel(t('connections')),controls=el('div',null,'control-row'),providers=providerDescriptors();
    append(wrap,el('p',t('connectionsNote'),'muted coverage-note'));
    controls.append(optionFilter('connection-provider','provider',providers.map(provider=>[provider.id,provider.displayName]),connectionProvider,value=>{connectionProvider=value;render();},'allProviders'));
    const refresh=button(t('refreshConnections'),()=>loadConnections());refresh.disabled=connectionsBusy;controls.append(refresh);wrap.append(controls);
    if(connectionsError){const error=el('p',t('connectionsUnavailable'),'notice');error.setAttribute('role','alert');wrap.append(error);}
    if(!cloudConnections){empty(wrap,connectionsBusy?'loading':'connectionsUnavailable');$('view').append(wrap);return;}
    wrap.append(el('p',`${t('connectionObserved')}: ${date(cloudConnections.observedAtUtc)} · ${t('connectionTestNote')}`,'muted'));
    const cards=el('div',null,'ops-connections');
    providers.filter(provider=>connectionProvider==='all'||connectionProvider===provider.id).forEach(provider=>{
        const data=cloudConnections.providers.find(item=>item?.providerId===provider.id);
        if(!data)return;
        const card=el('section',null,'ops-cloud-card ops-connection-card');card.dataset.provider=provider.id;
        const label=value=>t(connectionStateLabels[value]||'unknown');
        append(card,el('h3',provider.displayName),facts([['connectionScope',t(data.scopeStatus==='configured'?'connectionScopeReady':'connectionScopeMissing')],['connectionCredential',label(data.credentialStatus)],['connectionTool',label(data.toolStatus)],['connectionAccess',label(data.accessStatus)]]));
        if(validatedCloudActions().some(action=>action.actionKey===data.lastActionKey))card.append(el('p',`${data.lastActionKey} · ${date(data.lastObservedAtUtc)}`,'muted'));
        const guide=data.guide,details=el('details');details.open=connectionProvider!=='all';details.append(el('summary',t('connectionGuide')));
        if(guide&&typeof guide==='object'){
            const links=el('div',null,'ops-connection-links');
            append(links,connectionLink(provider.id,guide.signUpUrl,'connectionSignup'),connectionLink(provider.id,guide.consoleUrl,'connectionConsole'),connectionLink(provider.id,guide.documentationUrl,'connectionDocs'));details.append(links);
            const steps=el('ol',null,'ops-connection-steps');
            if(Array.isArray(guide.steps))guide.steps.slice(0,8).forEach(step=>{
                if(!step||typeof step!=='object')return;
                const item=el('li');append(item,el('h4',safeConnectionText(step.title,160)),el('p',safeConnectionText(step.description),'muted'));
                const command=safeConnectionText(step.commandTemplate,300);
                if(/^[\w <>.=\-]+$/.test(command)&&(/^(az login|aws sso login|gcloud auth)\b/.test(command)||command.startsWith('opscope serve --cloud '+provider.id+' ')))item.append(el('pre',command,'evidence'));
                steps.append(item);
            });
            if(steps.children.length)append(details,el('h4',t('connectionSteps')),steps);
        }
        const requirements=Array.isArray(data.requirements)?data.requirements.filter(item=>item&&connectionRequirementNames.has(item.name)).slice(0,8):[];
        if(requirements.length){const list=el('ul',null,'ops-connection-requirements');requirements.forEach(requirement=>{const operations=Array.isArray(requirement.operations)?requirement.operations.filter(operation=>knownOperations.has(operation)).map(operation=>t(operation==='drift'?'cloudDrift':operation)):[];list.append(el('li',`${requirement.name}: ${label(requirement.state)}${operations.length?' · '+operations.join(', '):''}`));});append(details,el('h4',t('connectionRequirements')),list);}
        card.append(details);
        const testActions=Array.isArray(data.testActions)?data.testActions:[],actions=validatedCloudActions().filter(action=>action.providerId===provider.id&&['inventory','health','networks','metrics'].includes(action.operation)&&testActions.some(test=>test?.actionKey===action.actionKey&&test.operation===action.operation&&test.scopeAlias===action.scopeAlias));
        const tests=el('div',null,'ops-cloud-actions');actions.forEach(action=>{const test=configureCloudButton(button(`${t('connectionTest')} · ${action.actionKey}`,()=>{cloudProvider=action.providerId;cloudScope=action.scopeAlias;navigate('cloud');runCloudQuery(action);}),action,'test');test.disabled=cloudBusy||cloudWaitSeconds(action)>0;tests.append(test);});
        if(!actions.length)card.append(el('p',t('connectionNoTest'),'muted'));else append(card,el('p',t('connectionTestNote'),'muted'),tests);
        cards.append(card);
    });wrap.append(cards);$('view').append(wrap);updateCloudControls();
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

const configurationSources={cloudflare:'cloudflare-fixed-configuration-get',alibaba:'aliyun-fixed-projections',scaleway:'scaleway-vpc-v2',ibm:'ibm-vpc-fixed-read',digitalocean:'digitalocean-project-fixed-read'};
const configurationChecks={cloudflare:['tls','dns','waf','routes'],alibaba:['disks','security-groups'],scaleway:['vpcs','private-networks'],ibm:['vpcs','subnets','security-groups'],digitalocean:['project-resources','droplets','volumes','load-balancers','vpcs','firewalls']};
const configurationTitles={tls:'configurationTls',dns:'configurationDns',waf:'configurationWaf',routes:'configurationRoutes',disks:'configurationDisks','security-groups':'configurationGroups',vpcs:'configurationVpcs',subnets:'configurationSubnets','private-networks':'configurationPrivateNetworks','project-resources':'configurationProjectResources',droplets:'configurationDroplets',volumes:'configurationVolumes','load-balancers':'configurationLoadBalancers',firewalls:'configurationFirewalls'};
const configurationFields={
    tls:[['sslMode','configurationSsl','ssl'],['minimumTlsVersion','configurationMinimumTls','tls'],['alwaysUseHttps','configurationHttps','boolean']],
    dns:[['observedRecords','configurationRecords'],['observedProxiedRecords','configurationProxied'],['observedUnproxiedRecords','configurationUnproxied'],['unknownProxyRecords','configurationProxyUnknown']],
    waf:[['observedRulesets','configurationRulesets'],['phasesObserved','configurationPhases'],['observedRules','configurationRules'],['observedEnabledRules','configurationEnabledRules'],['observedDisabledRules','configurationDisabledRules'],['unknownEnabledRules','configurationUnknownRules']],
    routes:[['observedRoutes','configurationRoutesRead']],
    disks:[['disksRead','configurationDisksRead'],['unencryptedDisks','configurationUnencrypted'],['unknownEncryption','configurationEncryptionUnknown']],
    'security-groups':[['groupsRead','configurationGroupsRead'],['rulesRead','configurationRules'],['worldIngressAllowRules','configurationWorldIngress'],['administrativeIngressAllowRules','configurationAdminIngress'],['possiblyShadowedAdminAllowRules','configurationShadowed'],['unknownRules','configurationUnknownRules']],
    vpcs:[['observedResources','configurationResources'],['expectedResources','configurationExpected']],
    'private-networks':[['observedResources','configurationResources'],['expectedResources','configurationExpected']]
};
const regionalConfigurationFields=[['observedResources','configurationResources'],['expectedResources','configurationExpected']];
const projectConfigurationFields=[['observedResources','configurationObservedResources'],['expectedResources','configurationExpectedResources']];
const configurationFieldsFor=(provider,check)=>provider==='digitalocean'?projectConfigurationFields:provider==='ibm'?regionalConfigurationFields:configurationFields[check];
const configurationRecordTypes=new Set(['A','AAAA','CNAME','MX','NS','TXT','SOA','SRV','PTR','CAA','DNSKEY','DS','RRSIG','NAPTR','TLSA','HTTPS','SVCB','URI','CERT','LOC','SSHFP','SMIMEA']);
function ibmScopeVerification(evidence){
    const scope=evidence?.scopeVerification,source=scope?.source==='ibm-resource-manager-v2'?scope.source:'unknown',failure=normalizedCoverage(scope?.state);
    return {source,state:evidence?.source==='ibm-vpc-fixed-read'&&source!=='unknown'?(scope.state==='verified'?'verified':['denied','failed','notConfigured','notRequested','rateLimited','timed-out','unsupported'].includes(failure)?failure:'unknown'):'unknown'};
}
function digitalOceanScopeVerification(evidence){
    const scope=evidence?.scopeVerification,source=scope?.source==='digitalocean-project-v2'?scope.source:'unknown',failure=normalizedCoverage(scope?.state);
    return {source,state:evidence?.source==='digitalocean-project-fixed-read'&&source!=='unknown'?(scope.state==='verified'?'verified':['denied','failed','notConfigured','notRequested','rateLimited','timed-out','unsupported'].includes(failure)?failure:'unknown'):'unknown'};
}
function configurationValue(value,type) {
    if(type==='boolean')return typeof value==='boolean'?value:null;
    if(type==='ssl')return ['off','flexible','full','strict','origin_pull'].includes(value)?value:null;
    if(type==='tls')return ['1.0','1.1','1.2','1.3'].includes(value)?value:null;
    return Number.isSafeInteger(value)&&value>=0?value:null;
}
function projectConfigurationEvidence(evidence,provider,state,operation) {
    const scopeVerification=provider==='ibm'?ibmScopeVerification(evidence):provider==='digitalocean'?digitalOceanScopeVerification(evidence):null;
    const supported=provider==='digitalocean'?(operation==='inventory'?['project-resources','droplets','volumes','load-balancers','vpcs']:operation==='posture'?['project-resources','droplets','firewalls']:[]):configurationChecks[provider]||[], observed=['complete','partial','noDataCoverage'].includes(state)&&(!scopeVerification||scopeVerification.state==='verified');
    const checks=Array.isArray(evidence?.checks)?evidence.checks.filter(check=>check&&typeof check==='object'&&supported.includes(check.check)).slice(0,100).map(check=>{
        const declaredState=normalizedCoverage(check.state)||'unknown';
        const timestamp=typeof check.observedAtUtc==='string'?Date.parse(check.observedAtUtc):NaN;
        const time=Number.isFinite(timestamp)&&timestamp<=Date.now()+120000?new Date(timestamp).toISOString():null;
        const checkState=!observed?state:['complete','partial','noDataCoverage'].includes(declaredState)&&!time?'unknown':declaredState;
        const values=observed&&['complete','partial','noDataCoverage'].includes(checkState)&&time&&check.observations&&typeof check.observations==='object'&&!Array.isArray(check.observations)?check.observations:null;
        const observations=values?Object.fromEntries(configurationFieldsFor(provider,check.check).map(([field,,type])=>[field,configurationValue(values[field],type)])):null;
        if(observations&&check.check==='dns')observations.recordTypes=Array.isArray(values.recordTypes)?values.recordTypes.filter(row=>row&&configurationRecordTypes.has(row.type)&&Number.isSafeInteger(row.count)&&row.count>=0).slice(0,50).map(row=>({type:row.type,count:row.count})):[];
        return {check:check.check,state:checkState,observedAtUtc:time,observations};
    }):[];
    const source=configurationSources[provider];
    return {source:typeof source==='string'&&evidence?.source===source?source:'unknown',...(scopeVerification?{scopeVerification}:{}),checks};
}
function cloudConfigurationEvidence(evidence,provider) {
    const section=el('section',null,'report-group ops-configuration-evidence');
    append(section,el('h3',t('configurationEvidence')),el('p',t('configurationNote'),'coverage-note muted'));
    section.append(facts([['source',evidence.source]]));
    if(evidence.scopeVerification)section.append(facts([[provider==='digitalocean'?'digitalOceanScope':'configurationScopeVerification',t(evidence.scopeVerification.state==='verified'?(provider==='digitalocean'?'digitalOceanScopeVerified':'configurationScopeVerified'):'configurationScopeUnknown')]]));
    evidence.checks.forEach((check,index)=>{
        const item=el('article',null,'ops-configuration-check');item.dataset.check=check.check;
        append(item,el('h4',`${t(configurationTitles[check.check])} · ${index+1}`));
        const status=el('span',cloudStatus(check.state),'ops-cloud-status');status.dataset.state=check.state;item.append(status);
        item.append(facts([['cloudObserved',date(check.observedAtUtc)]]));
        if(check.state==='partial')item.append(el('p',t('observedOnly'),'coverage-note muted'));
        if(!check.observations)item.append(el('p',t('configurationUnavailable'),'empty'));
        else {
            item.append(facts(configurationFieldsFor(provider,check.check).map(([field,label,type])=>{
                const value=check.observations[field];
                return [label,value===null?t('unknown'):type==='boolean'?t(value?'configurationEnabled':'configurationDisabled'):value];
            })));
            if(check.check==='dns'&&check.observations.recordTypes.length)item.append(table(['configurationRecordType','rows'],check.observations.recordTypes.map(row=>[row.type,row.count]),'cloud:configuration-dns:'+index));
        }
        section.append(item);
    });
    if(!evidence.checks.length)section.append(el('p',t('configurationNoChecks'),'empty'));
    return section;
}

const cloudObject=value=>value&&typeof value==='object'&&!Array.isArray(value)?value:{};
const cloudCount=value=>Number.isInteger(value)&&value>=0&&value<=2147483647?value:null;
const cloudBoolean=value=>typeof value==='boolean'?value:null;
const cloudIdentifier=value=>typeof value==='string'&&/^\[redacted-(?:identifier|host|service|process)(?:-[0-9]{1,4})?\]$/.test(value)?value:null;
const gkeStates=['STATUS_UNSPECIFIED','PROVISIONING','RUNNING','RECONCILING','STOPPING','ERROR','DEGRADED'];
const gkePoolStates=['STATUS_UNSPECIFIED','PROVISIONING','RUNNING','RUNNING_WITH_ERROR','RECONCILING','STOPPING','ERROR'];
const gkeEnum=(value,allowed)=>allowed.includes(value)?value:null;
const gkeVersion=value=>typeof value==='string'&&/^[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,5}(?:-gke\.[0-9]{1,10})?$/.test(value)?value:null;
function projectNodePools(value,state,budget) {
    const evidence=cloudObject(value), observed=['complete','partial'].includes(state), rows=Array.isArray(evidence.pools)?evidence.pools:[];
    let complete=observed&&evidence.state==='complete'&&Array.isArray(evidence.pools);
    const allowed=observed&&['complete','partial'].includes(evidence.state)&&Array.isArray(evidence.pools);
    const pools=[];
    if(allowed)for(const row of rows.slice(0,Math.min(100,budget.remaining))){
        budget.remaining--;
        const pool=cloudObject(row), resourceId=cloudIdentifier(pool.resourceId);
        if(!resourceId){complete=false;continue;}
        const autoscaling=cloudObject(pool.autoscaling),management=cloudObject(pool.management);
        if(pool.autoscaling!==undefined&&pool.autoscaling!==null&&pool.autoscaling!==autoscaling||pool.management!==undefined&&pool.management!==null&&pool.management!==management)complete=false;
        const projected={resourceId,state:gkeEnum(pool.state,gkePoolStates),version:gkeVersion(pool.version),initialNodeCount:cloudCount(pool.initialNodeCount),autoscaling:{enabled:cloudBoolean(autoscaling.enabled),minNodeCount:cloudCount(autoscaling.minNodeCount),maxNodeCount:cloudCount(autoscaling.maxNodeCount),totalMinNodeCount:cloudCount(autoscaling.totalMinNodeCount),totalMaxNodeCount:cloudCount(autoscaling.totalMaxNodeCount),locationPolicy:gkeEnum(autoscaling.locationPolicy,['LOCATION_POLICY_UNSPECIFIED','BALANCED','ANY'])},management:{autoRepair:cloudBoolean(management.autoRepair),autoUpgrade:cloudBoolean(management.autoUpgrade)}};
        // EN: Optional omissions remain unknown; invalid supplied values cannot support complete coverage.
        // ES: Las omisiones opcionales siguen siendo desconocidas; los valores inválidos no avalan cobertura completa.
        for(const [source,target] of [[pool,projected],[autoscaling,projected.autoscaling],[management,projected.management]])for(const key of Object.keys(target))if(key!=='resourceId'&&source[key]!==undefined&&source[key]!==null&&target[key]===null)complete=false;
        pools.push(projected);
    }
    if(pools.length!==rows.length)complete=false;
    const observedCount=allowed&&cloudCount(evidence.observedCount)===pools.length?cloudCount(evidence.observedCount):null;
    const returnedCount=allowed&&cloudCount(evidence.returnedCount)!==null&&evidence.returnedCount>=rows.length?evidence.returnedCount:null;
    if(observedCount===null||returnedCount===null||returnedCount!==pools.length)complete=false;
    return {state:!observed?state:complete?'complete':'partial',observedCount,returnedCount,pools};
}
function projectMetadataResources(resources,provider,state,operation,configuration) {
    if(provider==='digitalocean')return projectDigitalOceanResources(resources,state,operation,configuration);
    const budget={remaining:1000},observed=['complete','partial'].includes(state);
    return resources.slice(0,10000).map(resource=>{
        if(!resource||typeof resource!=='object')return null;
        const type=resource.type,properties=cloudObject(resource.properties);
        const gke=provider==='gcp'&&type==='gke.cluster',ibm=provider==='ibm'&&['network.vpc','network.subnet','network.securityGroup'].includes(type);
        if(!gke&&!ibm&&!(provider==='gcp'&&['sql.instance','run.service','storage.bucket'].includes(type)))return null;
        let projected;
        if(gke)projected={state:observed?gkeEnum(properties.state,gkeStates):null,masterVersion:observed?gkeVersion(properties.masterVersion):null,nodeVersion:observed?gkeVersion(properties.nodeVersion):null,nodeCount:observed?cloudCount(properties.nodeCount):null,nodePools:projectNodePools(properties.nodePools,state,budget)};
        else if(type==='sql.instance'){
            const numeric=typeof properties.diskSizeGb==='string'&&/^[0-9]{1,15}$/.test(properties.diskSizeGb)?Number(properties.diskSizeGb):properties.diskSizeGb;
            projected={state:gkeEnum(properties.state,['SQL_INSTANCE_STATE_UNSPECIFIED','RUNNABLE','SUSPENDED','PENDING_DELETE','PENDING_CREATE','MAINTENANCE','FAILED','ONLINE_MAINTENANCE']),databaseVersion:typeof properties.databaseVersion==='string'&&/^[A-Z][A-Z0-9_]{0,63}$/.test(properties.databaseVersion)?properties.databaseVersion:null,tier:typeof properties.tier==='string'&&/^db-[a-z0-9-]{1,80}$/.test(properties.tier)?properties.tier:null,availabilityType:gkeEnum(properties.availabilityType,['ZONAL','REGIONAL']),backupsEnabled:cloudBoolean(properties.backupsEnabled),storageAutoResize:cloudBoolean(properties.storageAutoResize),diskSizeGb:Number.isSafeInteger(numeric)&&numeric>=0?numeric:null};
        }
        else if(type==='run.service'){
            const numeric=typeof properties.observedGeneration==='string'&&/^[0-9]{1,15}$/.test(properties.observedGeneration)?Number(properties.observedGeneration):properties.observedGeneration;
            projected={state:gkeEnum(properties.state,['True','False','Unknown']),ingress:gkeEnum(properties.ingress,['all','internal','internal-and-cloud-load-balancing']),lastUpdatedAtUtc:null,observedGeneration:Number.isSafeInteger(numeric)&&numeric>=0?numeric:null,readyRevisionObserved:cloudBoolean(properties.readyRevisionObserved)};
        }
        else if(type==='storage.bucket')projected={state:gkeEnum(properties.state,['configuration-observed']),storageClass:gkeEnum(properties.storageClass,['STANDARD','NEARLINE','COLDLINE','ARCHIVE','MULTI_REGIONAL','REGIONAL','DURABLE_REDUCED_AVAILABILITY']),uniformBucketLevelAccess:cloudBoolean(properties.uniformBucketLevelAccess),publicAccessPrevention:gkeEnum(properties.publicAccessPrevention,['enforced','inherited','unspecified'])};
        else if(type==='network.vpc')projected={status:observed?gkeEnum(properties.status,['available','deleting','failed','pending']):null,classicAccess:observed?cloudBoolean(properties.classicAccess):null};
        else if(type==='network.subnet')projected={status:observed?gkeEnum(properties.status,['available','deleting','failed','pending']):null,ipVersion:observed?gkeEnum(properties.ipVersion,['ipv4']):null,vpc:observed?cloudIdentifier(properties.vpc):null};
        else projected={ruleCount:observed?cloudCount(properties.ruleCount):null,targetCount:observed?cloudCount(properties.targetCount):null,vpc:observed?cloudIdentifier(properties.vpc):null};
        if(!observed&&!gke)projected=Object.fromEntries(Object.keys(projected).map(key=>[key,null]));
        return {provider,id:cloudIdentifier(resource.id),type,name:cloudIdentifier(resource.name),properties:projected};
    }).filter(Boolean);
}
function projectDigitalOceanResources(resources,state,operation,configuration){
    const checks={'compute.vm':'droplets','storage.volume':'volumes','network.load-balancer':'load-balancers','network.vpc':'vpcs','network.firewall':'firewalls'};
    return resources.slice(0,1000).map(resource=>{
        if(!resource||typeof resource!=='object')return null;
        const type=resource.type,properties=cloudObject(resource.properties);
        if(operation==='inventory'&&type==='network.firewall'||operation==='posture'&&!['compute.vm','network.firewall'].includes(type))return null;
        const check=configuration?.checks.find(check=>check.check===checks[type]);
        const observed=['complete','partial'].includes(state)&&['complete','partial'].includes(check?.state)&&check?.observations!==null;
        let projected;
        if(type==='compute.vm')projected={state:gkeEnum(properties.state,['new','active','off','archive']),vcpus:cloudCount(properties.vcpus),memoryMb:cloudCount(properties.memoryMb),diskGb:cloudCount(properties.diskGb),vpc:cloudIdentifier(properties.vpc)};
        else if(type==='storage.volume')projected={sizeGigabytes:cloudCount(properties.sizeGigabytes)};
        else if(type==='network.load-balancer')projected={state:gkeEnum(properties.state,['new','active','errored']),type:gkeEnum(properties.type,['REGIONAL','REGIONAL_NETWORK','GLOBAL']),network:gkeEnum(properties.network,['EXTERNAL','INTERNAL']),sizeUnit:cloudCount(properties.sizeUnit),redirectHttpToHttps:cloudBoolean(properties.redirectHttpToHttps),proxyProtocol:cloudBoolean(properties.proxyProtocol),vpc:cloudIdentifier(properties.vpc)};
        else if(type==='network.vpc')projected={defaultNetwork:cloudBoolean(properties.defaultNetwork),relation:properties.relation==='referenced-by-project-resource'?properties.relation:null,referringResourceCount:cloudCount(properties.referringResourceCount)};
        else if(type==='network.firewall')projected={state:gkeEnum(properties.state,['waiting','succeeded','failed']),directDropletCount:cloudCount(properties.directDropletCount),tagDropletCount:cloudCount(properties.tagDropletCount),observedDropletCount:cloudCount(properties.observedDropletCount),inboundRuleCount:cloudCount(properties.inboundRuleCount),observedGlobalIngressRuleCount:cloudCount(properties.observedGlobalIngressRuleCount)};
        else return null;
        if(!observed)projected=Object.fromEntries(Object.keys(projected).map(key=>[key,null]));
        return {provider:'digitalocean',id:cloudIdentifier(resource.id),type,name:cloudIdentifier(resource.name),properties:projected};
    }).filter(Boolean);
}
function cloudDigitalOceanEvidence(operation){
    const section=el('section',null,'report-group ops-digitalocean-evidence');
    append(section,el('h3',t('digitalOceanEvidence')),el('p',t('digitalOceanScopeNote'),'coverage-note muted'),el('p',t('digitalOceanCountsNote'),'coverage-note muted'),el('p',t(operation==='posture'?'digitalOceanFirewallNote':'digitalOceanVpcNote'),'coverage-note muted'));
    return section;
}
function cloudRunServiceEvidence(resources){
    const section=el('section',null,'report-group ops-run-evidence');
    append(section,el('h3',t('runEvidence')),el('p',t('runNote'),'coverage-note muted'));
    const known=value=>value===null?t('unknown'):value;
    section.append(table(['identity','runState','runIngress','runLastUpdated','runReadyRevision'],resources.filter(resource=>resource.type==='run.service').map(resource=>[resource.id||t('unknown'),known(resource.properties.state),known(resource.properties.ingress),t('unknown'),resource.properties.readyRevisionObserved===null?t('unknown'):t(resource.properties.readyRevisionObserved?'runRevisionPresent':'runRevisionMissing')]),'cloud:run-services'));
    return section;
}
function cloudNodePoolEvidence(resources) {
    const section=el('section',null,'report-group ops-node-pool-evidence');
    append(section,el('h3',t('nodePoolEvidence')),el('p',t('nodePoolNote'),'coverage-note muted'));
    resources.filter(resource=>resource.type==='gke.cluster').forEach((resource,index)=>{
        const item=el('article',null,'ops-node-pool-cluster'),evidence=resource.properties.nodePools;
        item.dataset.cluster=String(index);append(item,el('h4',`${t('nodePoolCluster')} · ${index+1}`));
        const badge=el('span',cloudStatus(evidence.state),'ops-cloud-status');badge.dataset.state=evidence.state;item.append(badge);
        const count=value=>value===null?t('unknown'):evidence.state==='partial'?`${value} · ${t('observedOnly')}`:value;
        item.append(facts([['identity',resource.id||t('unknown')],['nodePoolObserved',count(evidence.observedCount)],['nodePoolReturned',count(evidence.returnedCount)]]));
        if(!['complete','partial'].includes(evidence.state))item.append(el('p',t('nodePoolUnavailable'),'empty'));
        else if(evidence.state==='complete'&&evidence.observedCount===0)item.append(el('p',t('nodePoolEmpty'),'empty'));
        else if(evidence.state==='partial')item.append(el('p',t('observedOnly'),'coverage-note muted'));
        evidence.pools.forEach((pool,poolIndex)=>{
            const detail=el('section',null,'ops-node-pool');append(detail,el('h5',`${t('identity')} · ${poolIndex+1}`),el('p',pool.resourceId,'muted'));
            const flag=value=>value===null?t('unknown'):t(value?'configurationEnabled':'configurationDisabled');
            const known=value=>value===null?t('unknown'):value;
            detail.append(facts([['nodePoolState',known(pool.state)],['nodePoolVersion',known(pool.version)],['nodePoolInitial',known(pool.initialNodeCount)],['nodePoolAutoscaling',flag(pool.autoscaling.enabled)],['nodePoolMin',known(pool.autoscaling.minNodeCount)],['nodePoolMax',known(pool.autoscaling.maxNodeCount)],['nodePoolTotalMin',known(pool.autoscaling.totalMinNodeCount)],['nodePoolTotalMax',known(pool.autoscaling.totalMaxNodeCount)],['nodePoolPolicy',known(pool.autoscaling.locationPolicy)],['nodePoolRepair',flag(pool.management.autoRepair)],['nodePoolUpgrade',flag(pool.management.autoUpgrade)]]));item.append(detail);
        });section.append(item);
    });return section;
}

function cloudBillingEvidence(billing, state) {
    const section=el('section',null,'report-group ops-billing-evidence');
    append(section,el('h3',t('billingEvidence')),el('p',t('billingNote'),'coverage-note muted'));
    const observed=['complete','partial'].includes(state);
    const count=value=>observed&&Number.isSafeInteger(value)&&value>=0?value:t('unknown');
    section.append(facts([['source',billing.source || t('unknown')],['billingRowsRead',count(billing.rowsRead)],['billingMatchedRows',count(billing.matchedRows)],['billingPeriodStart',date(billing.periodStartUtc)],['billingPeriodEnd',date(billing.periodEndUtc)]]));
    const currencies=observed&&Array.isArray(billing.currencySubtotals)?billing.currencySubtotals.filter(row=>row&&typeof row==='object'&&typeof row.currency==='string'&&/^[A-Z]{3}$/.test(row.currency)&&Number.isFinite(row.observedCost)).slice(0,20):[];
    const amount=value=>typeof value==='number'&&Number.isFinite(value)?value.toLocaleString(lang==='es'?'es-ES':'en-GB',value!==0&&Math.abs(value)<1e-6?{notation:'scientific',maximumSignificantDigits:10}:{minimumFractionDigits:2,maximumFractionDigits:9}):t('unknown');
    if(currencies.length) section.append(table(['currency','billingCost','billingCredits','billingNetCost','rows'],currencies.map(row=>[row.currency,amount(row.observedCost),amount(row.observedCredits),amount(row.observedNetCost),count(row.observedRows)]),'cloud:billing'));
    else section.append(el('p',t(observed?'billingNoRows':'billingUnavailable'),'empty'));
    return section;
}

function cloudSccEvidence(scc,state) {
    const section=el('section',null,'report-group ops-scc-evidence'), observed=['complete','partial'].includes(state);
    append(section,el('h3',t('sccEvidence')),el('p',t('sccNote'),'coverage-note muted'));
    section.append(facts([['source',scc.source || t('unknown')],['scope',scc.scopeKind || t('unknown')],['sccLocation',scc.location || t('unknown')],['sccCount',observed&&Number.isSafeInteger(scc.findingsCount)&&scc.findingsCount>=0?scc.findingsCount:t('unknown')]]));
    const records=observed&&Array.isArray(scc.findings)?scc.findings.filter(row=>row&&typeof row==='object').slice(0,500):[];
    if(records.length)section.append(table(['category','severity','state','observation'],records.map(row=>[row.category || t('unknown'),row.severity || t('unknown'),row.state || t('unknown'),date(row.eventTimeUtc)]),'cloud:scc'));
    return section;
}

function cloudPatchEvidence(patches,state) {
    const section=el('section',null,'report-group ops-patch-evidence'), observed=['complete','partial'].includes(state);
    append(section,el('h3',t('patchEvidence')),el('p',t('patchNote'),'coverage-note muted'));
    const count=value=>observed&&Number.isSafeInteger(value)&&value>=0?value:t('unknown');
    section.append(facts([['source',patches.source || t('unknown')],['patchCompliance',t('patchUnknown')],['patchJobsRead',count(patches.jobsRead)],['patchFreshness',Number.isFinite(patches.freshnessThresholdHours)&&patches.freshnessThresholdHours>0?`${patches.freshnessThresholdHours} h`:t('unknown')],['patchLatestUpdate',observed?date(patches.latestObservedJobUpdateUtc):t('unknown')]]));
    const jobs=observed&&Array.isArray(patches.jobs)?patches.jobs.filter(job=>job&&typeof job==='object').slice(0,1000):[];
    if(jobs.length)section.append(table(['identity','patchJobState','patchDryRun','patchUpdated','sampleAge','patchSucceeded','patchFailed'],jobs.map(job=>[job.resourceId || t('unknown'),job.state || t('unknown'),job.dryRun===true?t('patchDryRunYes'):job.dryRun===false?t('patchDryRunNo'):t('unknown'),date(job.updatedAtUtc),job.isStale===true?t('patchStale'):job.isStale===false?t('patchFresh'):t('unknown'),count(job.succeededInstanceCount),count(job.failedInstanceCount)]),'cloud:patch-jobs'));
    else section.append(el('p',t(observed?'patchNoJobs':'patchUnavailable'),'empty'));
    return section;
}

function cloudDriftEvidence(drift,state) {
    const section=el('section',null,'report-group ops-drift-evidence'), observed=['complete','partial'].includes(state), absence=observed&&drift.absenceAssessmentAvailable===true;
    append(section,el('h3',t('cloudDriftEvidence')),el('p',t('cloudDriftNote'),'coverage-note muted'));
    const count=value=>observed&&Number.isSafeInteger(value)&&value>=0?value:t('unknown');
    section.append(facts([['cloudDriftBaseline',date(drift.baselineObservedAtUtc)],['cloudDriftCurrent',date(drift.currentObservedAtUtc)],['cloudDriftCompared',count(drift.comparedResources)],['cloudDriftFields',count(drift.comparedFields)],['cloudDriftUnknown',count(drift.unknownFields)],['cloudDriftChanged',count(drift.changedResources)],['cloudDriftAdded',absence?count(drift.addedResources):t('unknown')],['cloudDriftMissing',absence?count(drift.missingResources):t('unknown')],['cloudDriftAbsence',t(absence?'cloudDriftAbsenceYes':'cloudDriftAbsenceNo')]]));
    const changes=observed&&Array.isArray(drift.changes)?drift.changes.filter(change=>change&&typeof change==='object'&&(change.changeType==='Changed'||absence&&['Added','Missing'].includes(change.changeType))).slice(0,1000):[];
    if(changes.length)section.append(table(['identity','category','change','cloudDriftFieldNames'],changes.map(change=>[change.resourceId || t('unknown'),change.type || t('unknown'),t('cloudDrift'+change.changeType+'Change'),Array.isArray(change.fields)?change.fields.filter(field=>['region','state'].includes(field)).join(', '):t('unknown')]),'cloud:inventory-drift'));
    else section.append(el('p',t(observed?'cloudDriftNoChanges':'cloudDriftUnavailable'),'empty'));
    return section;
}

function cloudClusterEvidence(cluster,correlation,state) {
    const section=el('section',null,'report-group ops-cluster-evidence');
    append(section,el('h3',t('clusterEvidence')),el('p',t('clusterNote'),'muted'));
    const links=['complete','partial'].includes(state)&&correlation?.nodeReferencesVerified===true&&correlation?.clusterIdentityVerified===false&&['verified_node_references','partial_node_references'].includes(correlation?.state)&&Array.isArray(correlation.links)?correlation.links.filter(link=>link&&typeof link==='object'&&link.state==='verified_node_reference'&&['gcp','azure'].includes(link.provider)).slice(0,1000):[];
    section.append(el('p',t(links.length?'clusterVerified':'clusterUnlinked'),'coverage-note muted'));
    section.append(el('p',t('clusterIdentityUnknown'),'coverage-note muted'));
    if(correlation&&typeof correlation==='object'){
        const count=value=>Number.isSafeInteger(value)&&value>=0?value:t('unknown');
        section.append(facts([['clusterNodesObserved',count(correlation.observedNodes)],['clusterNodesMatched',links.length?count(correlation.matchedNodes):t('unknown')],['clusterNodesUnmatched',count(correlation.unmatchedNodes)]]));
        if(links.length)section.append(table(['clusterNode','provider','identity','state'],links.map(link=>[link.nodeId||t('unknown'),link.provider,link.resourceId||t('unknown'),t('clusterNodeMatched')]),'cloud:node-references'));
        reportWarnings(section,Array.isArray(correlation.warnings)?correlation.warnings.filter(warning=>typeof warning==='string').slice(0,50):[]);
    }
    section.append(facts([['scope',t('clusterAdapter')],['clusterNamespaces',Number.isSafeInteger(cluster.namespacesQueried)&&cluster.namespacesQueried>=0?cluster.namespacesQueried:t('unknown')]]));
    return section;
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
        if(latest)section.append(el('p',`${t('latestValue')}: ${latest.value.toLocaleString(lang==='es'?'es-ES':'en-GB',{maximumSignificantDigits:8})} ${item.unit || t('unknown')}`,'ops-metric-latest'));
        const samples=el('details');append(samples,el('summary',`${t('evidence')} · ${t('showing')} ${Math.min(points.length,50)} / ${points.length}`),table(['observation','value','unit'],points.slice(-50).map(point=>[date(new Date(point.time).toISOString()),point.value,item.unit || t('unknown')]),`cloud:metrics:${index}`));
        if(points.length<2){empty(section,'cloudNeedSamples');section.append(samples);group.append(section);return;}
        const ns='http://www.w3.org/2000/svg',svg=document.createElementNS(ns,'svg');svg.setAttribute('viewBox','0 0 800 220');svg.setAttribute('role','img');svg.setAttribute('aria-labelledby',title.id);svg.classList.add('ops-chart__svg');
        const start=points[0].time,end=points[points.length-1].time,span=end-start || 1;
        const minimum=Math.min(...points.map(point=>point.value)),maximum=Math.max(...points.map(point=>point.value));
        const low=percentUnit?0:minimum,high=percentUnit?100:maximum===minimum?minimum+1:maximum;
        const add=(tag,attrs,text)=>{const node=document.createElementNS(ns,tag);Object.entries(attrs).forEach(([key,value])=>node.setAttribute(key,String(value)));if(text!==undefined)node.textContent=text;svg.append(node);return node;};
        const draw=()=>{
            if(!svg.isConnected){cloudPlotRenderers.delete(draw);return;}
            const viewport=Math.max(160,Math.min(2400,Math.round(svg.getBoundingClientRect().width || 800))),left=65,right=viewport-20,width=right-left;
            svg.setAttribute('viewBox',`0 0 ${viewport} 220`);svg.replaceChildren();
            for(const ratio of [0,.5,1]){const y=20+ratio*160,value=high-(high-low)*ratio,axis=percentUnit?number(value):value.toLocaleString(lang==='es'?'es-ES':'en-GB',{notation:'compact',maximumSignificantDigits:3});add('line',{x1:left,x2:right,y1:y,y2:y,stroke:'currentColor',opacity:'.2'});add('text',{x:left-9,y:y+4,'text-anchor':'end',fill:'currentColor','font-size':12},axis);}
            let path='',previous=null;const period=Number.isFinite(periodSeconds)&&periodSeconds>0?periodSeconds*1000:null;
            points.forEach(point=>{const x=left+(point.time-start)/span*width,y=20+(high-point.value)/(high-low)*160;const continuous=previous&&point.time>previous.time&&period!==null&&point.time-previous.time<=period*2.5;path+=(continuous?' L ':' M ')+x.toFixed(2)+' '+y.toFixed(2);if(!continuous)add('circle',{cx:x,cy:y,r:2.5,fill:'var(--accent)'});previous=point;});
            add('path',{d:path,fill:'none',stroke:'var(--accent)','stroke-width':2.5});
            const format={hour:'2-digit',minute:'2-digit'};
            add('text',{x:left,y:210,fill:'currentColor','font-size':12},new Date(start).toLocaleTimeString(lang,format));add('text',{x:right,y:210,fill:'currentColor','text-anchor':'end','font-size':12},new Date(end).toLocaleTimeString(lang,format));
        };
        section.append(svg);cloudPlotRenderers.add(draw);queueMicrotask(draw);
        section.append(samples);group.append(section);
    });return group;
}
function showCloud() {
    const wrap=panel(t('cloud')), providers=providerDescriptors(), actions=validatedCloudActions(), controls=el('div',null,'control-row');
    const help=button(t('connectionHelp'),()=>navigate('connections'));help.disabled=cloudBusy;
    append(wrap,el('p',t('cloudCatalogNote'),'muted'),el('p',t(actions.length?'cloudNote':'cloudUnavailable'),'muted workspace-note'),help);
    controls.append(optionFilter('cloud-provider','provider',providers.map(item=>[item.id,item.displayName]),cloudProvider,value=>{cloudProvider=value;cloudScope='all';cloudAction=null;cloudResult=null;cloudError=null;render();},'allProviders'));
    const scopes=[...new Set(actions.filter(action=>cloudProvider==='all'||action.providerId===cloudProvider).map(action=>action.scopeAlias))];
    controls.append(optionFilter('cloud-scope','scope',scopes.map(alias=>[alias,alias]),cloudScope,value=>{cloudScope=value;cloudAction=null;cloudResult=null;cloudError=null;render();},'allScopes'));
    controls.querySelectorAll('select').forEach(select=>select.disabled=cloudBusy);wrap.append(controls);
    const cards=el('div',null,'ops-cloud-matrix');
    providers.filter(provider=>cloudProvider==='all'||provider.id===cloudProvider).forEach(provider=>{
        const card=el('section',null,'ops-cloud-card'), configured=actions.filter(action=>action.providerId===provider.id&&(cloudScope==='all'||action.scopeAlias===cloudScope));
        card.dataset.provider=provider.id;
        append(card,el('h3',provider.displayName),el('p',t(provider.category==='cluster'?'clusterAdapter':'infrastructureAdapter'),'ops-adapter-kind muted'));
        if(provider.category==='cluster')card.append(el('p',t('clusterNote'),'muted'));
        const status=el('span',cloudStatus(configured.length?'configured':'not-configured'),'ops-cloud-status');status.dataset.state=configured.length?'configured':'notConfigured';card.append(status);
        if(!configured.length)card.append(el('p',t('cloudNoScope'),'muted'));
        const coverage=el('div',null,'status-counts');
        provider.operations.forEach(capability=>{
            const operation=capability.name, enabled=configured.some(action=>action.operation===operation);
            const state=enabled?'configured':'not-configured', item=el('span',`${t(operation==='drift'?'cloudDrift':operation)}: ${cloudStatus(state)}`,'ops-cloud-status');item.dataset.state=state;item.dataset.operation=operation;
            if(Array.isArray(capability.limitations))item.title=capability.limitations.filter(value=>typeof value==='string').join(' ');coverage.append(item);
        });card.append(coverage);
        if(!provider.operations.length)card.append(el('p',t('noAdvertisedOperations'),'muted'));
        const buttons=el('div',null,'ops-cloud-actions');
        configured.forEach(action=>{const query=configureCloudButton(button(`${t('run')} · ${action.actionKey}`,()=>runCloudQuery(action)),action);query.disabled=cloudBusy||cloudWaitSeconds(action)>0;buttons.append(query);});card.append(buttons);cards.append(card);
    });wrap.append(cards);
    if(cloudAction)wrap.append(el('p',`${t('source')}: ${cloudAction} · ${t('alwaysRedacted')}`,'source-badge'));
    if(cloudBusy){const status=el('p',t('cloudLoading'),'work-status');status.id='cloud-status';status.setAttribute('role','status');wrap.append(status);}
    else if(cloudError){const error=el('p',cloudError,'notice');error.id='cloud-error';error.setAttribute('role','alert');wrap.append(error);}
    else if(!cloudResult&&actions.length)empty(wrap,'cloudEmpty');
    if(cloudResult){
        const data=cloudResult.data, success=cloudResult.operationSucceeded!==false;
        const declaredState=normalizedCoverage(data?.coverage?.state);
        let state=!success&&['complete','noDataCoverage'].includes(declaredState)?'failed':declaredState||(!success?'failed':cloudResult.warnings?.length?'partial':'complete');
        const provider=validatedCloudActions().find(action=>action.actionKey===cloudAction)?.providerId;
        const digitalOceanProjection=provider==='digitalocean'&&['inventory','posture'].includes(cloudAction?.split('/')[1]);
        const metadataProjection=provider==='ibm'&&cloudAction?.endsWith('/networks')||provider==='gcp'&&cloudAction?.endsWith('/services')||digitalOceanProjection;
        if(metadataProjection&&provider==='ibm'&&ibmScopeVerification(data?.configurationEvidence).state!=='verified')state=normalizedCoverage(ibmScopeVerification(data?.configurationEvidence).state)||'failed';
        if(digitalOceanProjection&&digitalOceanScopeVerification(data?.configurationEvidence).state!=='verified')state=normalizedCoverage(digitalOceanScopeVerification(data?.configurationEvidence).state)||'failed';
        const count=Object.hasOwn(cloudObject(data?.coverage),'enumeratedResources')?cloudCount(data.coverage.enumeratedResources):Object.hasOwn(cloudObject(data),'resourceCount')?cloudCount(data.resourceCount):Array.isArray(data?.resources)?cloudCount(data.resources.length):null;
        const visibleCount=['complete','partial'].includes(state)&&count!==null?state==='partial'?`${count} · ${t('observedOnly')}`:count:t('unknown');
        const summary=el('section',null,'ops-cloud-result-summary');summary.append(el('h3',t('cloudResult')));
        const badge=el('span',cloudStatus(state),'ops-cloud-status');badge.dataset.state=state;summary.append(badge);
        const factsRows=[['source',cloudResult.kind || cloudAction],['cloudObserved',date(data?.coverage?.observedAtUtc || cloudResult.collectedAtUtc)]];
        if(metadataProjection||!data?.billing&&!data?.scc&&!data?.patches&&!data?.configurationEvidence)factsRows.push(['resourceCount',visibleCount]);
        summary.append(facts(factsRows));
        if(cloudReadMetadata){
            const metadata=el('section',null,'ops-cloud-cache');metadata.dataset.cache=cloudReadMetadata.cache;
            append(metadata,el('h4',t(cloudReadMetadata.cache==='hit'?'cloudCached':'cloudFresh')),el('p',t('cloudCacheNote'),'muted'));
            const age=el('span');age.dataset.cloudCacheAge='';const remaining=el('span');remaining.dataset.cloudCacheRemaining='';
            metadata.append(facts([['cloudCacheStored',date(cloudReadMetadata.cachedAtUtc)],['cloudCacheExpires',date(cloudReadMetadata.expiresAtUtc)]]));
            const counters=el('p',null,'muted');append(counters,el('span',t('cloudCacheAge')+': '),age,el('span',' · '+t('cloudCacheRemaining')+': '),remaining);metadata.append(counters);summary.append(metadata);
        }
        if(state==='partial')summary.append(el('p',t('observedOnly'),'coverage-note muted'));
        else if(!['complete'].includes(state))summary.append(el('p',t(state==='denied'?'cloudDenied':state==='timed-out'?'cloudTimeout':'cloudFailedCoverage'),'coverage-note muted'));
        else if(count===0&&!data?.configurationEvidence&&!['metrics','cost','scc'].includes(cloudAction?.split('/')[1]))summary.append(el('p',t('cloudEmptyCoverage'),'coverage-note muted'));
        reportWarnings(summary,cloudResult.warnings);
        if(!metadataProjection){
            if(data?.cluster&&typeof data.cluster==='object')summary.append(cloudClusterEvidence(data.cluster,data.infrastructureCorrelation,state));
            if(data?.billing&&typeof data.billing==='object')summary.append(cloudBillingEvidence(data.billing,state));
            if(data?.scc&&typeof data.scc==='object')summary.append(cloudSccEvidence(data.scc,state));
            if(data?.patches&&typeof data.patches==='object')summary.append(cloudPatchEvidence(data.patches,state));
            if(data?.drift&&typeof data.drift==='object')summary.append(cloudDriftEvidence(data.drift,state));
        }
        const configuration=(!metadataProjection||provider==='ibm'||digitalOceanProjection)&&data&&typeof data==='object'&&Object.hasOwn(data,'configurationEvidence')?projectConfigurationEvidence(data.configurationEvidence,provider,state,cloudAction?.split('/')[1]):null;
        if(configuration)summary.append(cloudConfigurationEvidence(configuration,provider));
        if(digitalOceanProjection)summary.append(cloudDigitalOceanEvidence(cloudAction?.split('/')[1]));
        if(cloudResult.findings?.length)summary.append(findingsList(cloudResult.findings,'cloud:findings'));
        if(!metadataProjection&&Array.isArray(data?.metrics))summary.append(cloudMetricSeries(data.metrics));
        const resources=metadataProjection?projectMetadataResources(Array.isArray(data?.resources)?data.resources:[],provider,state,cloudAction?.split('/')[1],configuration):Array.isArray(data?.resources)?data.resources:[];
        if(metadataProjection&&provider==='gcp'&&resources.some(resource=>resource.type==='gke.cluster'))summary.append(cloudNodePoolEvidence(resources));
        if(metadataProjection&&provider==='gcp'&&resources.some(resource=>resource.type==='run.service'))summary.append(cloudRunServiceEvidence(resources));
        if(resources.length)summary.append(table(['provider','name','category','state'],resources.map(item=>[item.provider || cloudAction?.split('/')[0],item.name || item.id,item.type,resourceState(item)]),'cloud:resources'));
        const projectedData=metadataProjection?{provider,coverage:{state,enumeratedResources:['complete','partial'].includes(state)?cloudCount(count):null,observedAtUtc:typeof data?.coverage?.observedAtUtc==='string'&&Number.isFinite(Date.parse(data.coverage.observedAtUtc))?new Date(data.coverage.observedAtUtc).toISOString():null},resources,...(configuration?{configurationEvidence:configuration}:{})}:configuration?{...data,configurationEvidence:configuration}:data;
        const projectedReport=metadataProjection?{kind:cloudResult.kind,collectedAtUtc:cloudResult.collectedAtUtc,operationSucceeded:cloudResult.operationSucceeded,findings:Array.isArray(cloudResult.findings)?cloudResult.findings.map(item=>Object.fromEntries(['severity','code','title','detail','recommendation'].filter(key=>Object.hasOwn(cloudObject(item),key)&&['string','number'].includes(typeof item[key])).map(key=>[key,item[key]]))):[],warnings:Array.isArray(cloudResult.warnings)?cloudResult.warnings.filter(item=>typeof item==='string'):[],data:projectedData}:configuration?{...cloudResult,data:projectedData}:cloudResult;
        const raw=el('details');raw.open=true;append(raw,el('summary',t(configuration?'configurationProjection':metadataProjection?'nodePoolProjection':'rawJson')));if(configuration||metadataProjection)raw.append(el('p',t(configuration?'configurationProjectionNote':'nodePoolProjectionNote'),'muted'));const evidenceJson=el('pre',JSON.stringify(projectedReport,null,2),'evidence');evidenceJson.tabIndex=0;raw.append(evidenceJson);summary.append(raw);wrap.append(summary);
    }
    $('view').append(wrap);updateCloudControls();
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
    const saved = view === 'analysis', redactedView = ['analysis','history','fleet','cloud','connections'].includes(view), context = $('source-context');
    const label = saved ? 'savedSource' : view === 'history' ? 'retainedSource' : view === 'fleet' ? 'fleetSource' : view === 'cloud' ? 'cloudSource' : view === 'connections' ? 'connectionSetup' : 'liveSource';
    let detail = snapshot ? date(snapshot.collectedAtUtc) : t('connecting');
    if (saved) detail = `${t('alwaysRedacted')} · ${analysisSafe ? date(analysisSafe.collectedAtUtc) : t('sourceEmpty')}`;
    else if (view === 'history') detail = `${t('alwaysRedacted')} · ${entries.length} ${t('retained')}`;
    else if (view === 'fleet') detail = `${t('alwaysRedacted')} · ${fleetSnapshots.length} ${t('fleetSelected')}`;
    else if (view === 'connections') detail = t('connectionsNote');
    else if (view === 'cloud') detail = `${t('alwaysRedacted')}${cloudAction ? ` · ${cloudAction}` : ''}`;
    if(pendingEvidence&&!redactedView)detail+=` · ${t('pendingEvidence')}`;
    context.replaceChildren(el('span', t(label), 'source-badge'), el('span', detail, 'muted'));
    context.classList.toggle('saved', redactedView);
    $('full').disabled = redactedView;
    document.querySelector('.full-toggle').hidden = redactedView;
    $('privacy').textContent = t(!redactedView && $('full').checked ? 'fullWarning' : 'redacted');
    context.setAttribute('aria-label', t('source'));
    $('collect').hidden = ['analysis','cloud','fleet','history','connections'].includes(view);
    document.querySelector('.search-wrap').hidden = redactedView;
    $('page-description').textContent = t(saved ? 'analysisDescription' : view === 'connections' ? 'connectionsDescription' : 'description');
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
    const target=$('search-results');target.replaceChildren();if(['analysis','history','fleet','cloud','connections'].includes(view)){target.hidden=true;return;}
    const query=$('search').value.trim();target.hidden=!query;if(!query||!snapshot)return;
    const groups=[['findings',snapshot.findings.filter(match).map(item=>item.title)],['processes',snapshot.processes.filter(match).map(item=>`${item.name} · ${item.id}`)],['portList',snapshot.listeners.filter(match).map(item=>`${item.protocol} · ${item.localAddress}`)],['services',snapshot.services.filter(match).map(item=>`${item.name} · ${item.state}`)]];
    const total=groups.reduce((sum,[,rows])=>sum+rows.length,0);target.append(el('p',`${total} ${t('searchCount')} · ${t('showing')} ${Math.min(total,30)}`,'search-summary'));
    let remaining=30;
    groups.forEach(([section,rows])=>{if(!rows.length||remaining<=0)return;target.append(el('h2',`${t(section)} (${rows.length})`,'search-group'));for(const text of rows.slice(0,remaining)){const node=button(text,()=>{navigate(section==='portList'?'processes':section);target.hidden=true;$('content').focus();});node.append(el('small',t(section)));target.append(node);remaining--;}});
    if(!total)target.append(el('p',t('searchEmpty'),'empty'));
}

function render(reason = 'explicit') {
    const target=$('view'), active=document.activeElement;
    if(reason==='sample'&&(target.contains(active)||['policy','fleet','analysis','drift','cloud','connections','reports','settings'].includes(view))){
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
    if (view === 'connections' && hasSession()) { showConnections(); return; }
    if (view === 'analysis' && hasSession()) {
        showAnalysis();
        $('collected-at').textContent = analysisSafe ? `${t('savedSource')}: ${date(analysisSafe.collectedAtUtc)}` : t('sourceEmpty');
        return;
    }
    if (!snapshot) { empty(target, hasSession() ? 'connecting' : 'noToken'); return; }
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
    while(!disposed&&hasSession()&&connectionState!=='disconnected'){
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
    if((event.ctrlKey||event.metaKey)&&event.key.toLowerCase()==='k'&&!['analysis','history','fleet','cloud','connections'].includes(view)){event.preventDefault();$('search').focus();}
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
(async()=>{
    try{
        if(!token){
            const response=await fetch('/api/session',{credentials:'same-origin',cache:'no-store',referrerPolicy:'no-referrer'});
            const session=response.ok?await response.json():null;
            if(session?.authenticationMode!=='proxy'||session.authenticated!==true||session.readOnly!==true){notice(t('noToken'));$('collect').disabled=true;return;}
            authenticationMode='proxy';translate();
        }
        [settings,capabilities]=await Promise.all([json('/api/settings'),json('/api/capabilities')]);
        const catalog=await json('/api/cloud/catalog').catch(()=>null);
        if(catalog?.version===2&&Array.isArray(catalog.providers)&&Array.isArray(catalog.actions))cloudCatalog=catalog;
        await loadConnections(false);
        if(capabilities.policy)policyResult=await json('/api/policy');
        await refresh();
        const history=await json('/api/metrics/history?window=30m&limit=720').catch(()=>null);
        const samples=Array.isArray(history)?history:Array.isArray(history?.samples)?history.samples:Array.isArray(history?.points)?history.points:[];
        for(const sample of samples){if(window.OpscopeCharts?.push(sample))lastMetricSequence=Math.max(lastMetricSequence,Number(sample.sequence)||0);}
        live();
    }catch(error){notice(error.message);setConnection('disconnected');}
})();
})();
