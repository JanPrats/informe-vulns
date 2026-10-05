// Nodo «CVEs sin avisar»: se queda con las CVEs de novedades.json que todavía no se han avisado.
// La primera ejecución activa solo las marca como avisadas, sin enviar nada, para no recibir de golpe
// todo lo de los últimos días. (Las ejecuciones manuales no guardan este estado: usa «probar».)
const cfg = $('Configuración').first().json;
const feed = $input.first().json;
const cves = feed.cves || [];
const estado = $getWorkflowStaticData('global');

let nuevas;
if (cfg.probar) {
  const pedidas = (cfg.cves_prueba || []).map(c => String(c).trim().toUpperCase());
  nuevas = pedidas.length
    ? cves.filter(r => pedidas.includes(r.cve))
    : [...cves].sort((a, b) => b.publicado.localeCompare(a.publicado)).slice(0, 3);
} else {
  if (!estado.avisadas) {
    estado.avisadas = {};
    const ahora = new Date().toISOString();
    for (const r of cves) estado.avisadas[r.cve] = ahora;
    return [];
  }
  nuevas = cves.filter(r => !(r.cve in estado.avisadas));
}

if (!nuevas.length) return [];
return [{ json: {
  nuevas,
  feed: { equivalencias: feed.equivalencias, plantillas: feed.plantillas, informe_url: feed.informe_url },
} }];
