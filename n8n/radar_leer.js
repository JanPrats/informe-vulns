// Nodo «Leer boletines»: lee los feeds oficiales de boletines.json y se queda con lo que NVD no ve
// (hardening sin CVE, preavisos, componentes de terceros). Misma lógica que boletines.py: si cambias una,
// cambia la otra. Devuelve un único elemento con el correo ya montado, o nada si no hay boletines nuevos.
// La primera ejecución activa solo los marca como avisados, sin enviar nada.
// Avisos vivos: de los de terceros se lee el detalle (página de Cisco y de FortiGuard, JSON de Palo Alto) y se
// guarda el estado de cada producto perimetral («huellas»); si cambia en un aviso ya avisado, va en el correo.
const cfg = $('Configuración').first().json;
const conf = await this.helpers.httpRequest({ url: cfg.reglas_url, json: true });
const estado = $getWorkflowStaticData('global');

const NOMBRES = { fortinet: 'Fortinet', paloalto: 'Palo Alto Networks', cisco: 'Cisco', checkpoint: 'Check Point',
  f5: 'F5', citrix: 'Citrix', watchguard: 'WatchGuard', forcepoint: 'Forcepoint', zscaler: 'Zscaler',
  netskope: 'Netskope', cloudflare: 'Cloudflare' };
const ENTIDADES = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ' };

// texto de un campo del XML: sin CDATA, con las entidades resueltas y sin etiquetas HTML
const texto = s => (s || '')
  .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1')
  .replace(/&#x([0-9a-f]+);/gi, (_, n) => String.fromCodePoint(parseInt(n, 16)))
  .replace(/&#(\d+);/g, (_, n) => String.fromCodePoint(Number(n)))
  .replace(/&(amp|lt|gt|quot|apos|nbsp);/g, (_, n) => ENTIDADES[n])
  .replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
// primer hijo con ese nombre, con o sin espacio de nombres (feedburner:origLink…)
const campo = (item, nombre) => {
  const m = item.match(new RegExp(`<(?:[\\w-]+:)?${nombre}\\b[^>]*>([\\s\\S]*?)</(?:[\\w-]+:)?${nombre}>`));
  return m ? texto(m[1]) : '';
};

function leerFeed(xml) {
  return (xml.match(/<(item|entry)\b[\s\S]*?<\/\1>/g) || []).map(item => {
    let url = campo(item, 'origLink') || campo(item, 'link');
    if (!url) { const h = item.match(/<link\b[^>]*href="([^"]+)"/); url = h ? h[1] : ''; }
    if (url.includes('vs_f=')) url = url.split('?')[0];       // Cisco: el resto es seguimiento del RSS
    let fecha = null;
    for (const c of ['pubDate', 'published', 'updated', 'date']) {
      let v = campo(item, c);
      if (/^\d{4}-\d\d-\d\d[ T][\d:.]+$/.test(v)) v = v.replace(' ', 'T') + 'Z';   // Cisco: sin zona = UTC, como en Python
      const d = new Date(v);
      if (v && !isNaN(d)) { fecha = d.toISOString(); break; }
    }
    const resumen = campo(item, 'description') || campo(item, 'summary');
    return { id: (campo(item, 'guid') || campo(item, 'id') || url).split('?')[0], titulo: campo(item, 'title'), url, fecha, resumen };
  });
}

function clasificar(titulo, tipo, r) {
  const t = titulo.toLowerCase();
  if (new RegExp(r.terceros).test(t)) return 'terceros';
  if (new RegExp(r.sin_cve).test(t)) return 'sin-cve';
  if (tipo === 'blog-psirt' || (tipo === 'blog' && new RegExp(r.blog).test(t))) return 'comunicado';
  return null;
}

// ---------- detalle de los avisos vivos (como en boletines.py: todo se lee como líneas de texto)
const ESTADOS = ['afectado', 'investigando', 'no afectado'];   // si un producto sale en dos listas, manda el primero
const MESES_EN = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec'];
const lineas = pagina => pagina
  .replace(/<(script|style)\b[\s\S]*?<\/\1>/gi, ' ')
  .replace(/<\/?(?:li|br|p|div|h\d|tr|td|th|dt|dd|ul|ol|table)\b[^>]*>/gi, '\n')
  .replace(/<[^>]+>/g, ' ')
  .replace(/&#x([0-9a-f]+);/gi, (_, n) => String.fromCodePoint(parseInt(n, 16)))
  .replace(/&#(\d+);/g, (_, n) => String.fromCodePoint(Number(n)))
  .replace(/&(amp|lt|gt|quot|apos|nbsp);/g, (_, n) => ENTIDADES[n])
  .split('\n').map(l => l.replace(/\s+/g, ' ').trim()).filter(Boolean);
const poner = (estado, p, v) => { if (!(p in estado) || ESTADOS.indexOf(v) < ESTADOS.indexOf(estado[p])) estado[p] = v; };
// una línea que nombra un producto perimetral, no una frase ni un comando («asa# show …») que lo menciona
const esProducto = (l, perim) => l.length <= 100 && !/[.:]$/.test(l) && !l.includes('#') && new RegExp(perim).test(l.toLowerCase());
const iso = (anio, mes, dia, hora = '00:00') =>
  `${String(anio).padStart(4, '0')}-${String(MESES_EN.indexOf(mes.slice(0, 3).toLowerCase()) + 1).padStart(2, '0')}-${String(dia).padStart(2, '0')}T${hora}:00Z`;

function cisco(ls, perim) {
  const sec = { 'products under investigation': 'investigando', 'vulnerable products': 'afectado',
    'products confirmed not vulnerable': 'no afectado' };
  const fin = /^(workarounds|fixed software|exploitation and public announcements|details|source)$/;
  const estado = {}; let actual = null;
  for (const l of ls) {
    const k = l.toLowerCase();
    if (Object.hasOwn(sec, k)) actual = sec[k];
    else if (fin.test(k)) actual = null;
    else if (actual && esProducto(l, perim)) poner(estado, l, actual);
  }
  const t = ls.join(' ');
  const m = t.match(/(?:Last Updated|First Published):\s*(\d{4}) ([A-Za-z]+) (\d{1,2}) (\d{1,2}:\d\d)/);
  const v = t.match(/\bVersion (\d+(?:\.\d+)+)/);
  let nota = '';
  const r = ls.indexOf('Revision History');
  if (r >= 0) { const d = ls.indexOf('Date', r); if (d >= 0 && ls.length > d + 2) nota = ls[d + 2]; }
  return { version: v ? v[1] : null, nota, estado, actualizado: m ? iso(m[1], m[2], m[3], m[4].padStart(5, '0')) : null };
}

function fortinet(ls, perim) {
  const fin = /^(solutions?|timeline|references|virtual patch|workarounds?|acknowledge?ments?|ir number)$/;
  // títulos de lista: «Products Under Investigation:», y en los avisos antiguos también «Affected Products»
  const titulo = /:$|^(the following )?products?\b|\bproducts?$/;
  const estado = {}; let actual = null, tabla = false, nota = '', actualizado = null, i = 0;
  while (i < ls.length) {
    const l = ls[i], k = l.toLowerCase();
    if (k === 'version' && ls[i + 1] === 'Affected' && ls[i + 2] === 'Solution') { actual = 'afectado'; tabla = true; i += 3; continue; }
    if (titulo.test(k) && k.length < 80 && !new RegExp(perim).test(k)) {
      tabla = false;
      actual = k.includes('investigation') ? 'investigando'
        : /\bnot (impacted|affected|vulnerable)/.test(k) ? 'no afectado'
        : /\b(impacted|affected|vulnerable)\b/.test(k) ? 'afectado' : null;
    } else if (fin.test(k)) {
      actual = null; tabla = false;
      if (k === 'timeline') {                                    // «2026-10-22: Products under investigation…»
        const fechas = ls.slice(i + 1, i + 30).filter(x => /^\d{4}-\d\d-\d\d:/.test(x)).sort();
        nota = fechas.length ? fechas[fechas.length - 1].slice(11).trim() : '';
      }
    } else if ((k === 'published date' || k === 'updated date') && i + 1 < ls.length) {   // «Updated Date» va después
      const m = ls[i + 1].match(/^([A-Za-z]{3})\w* (\d{1,2}), (\d{4})/);
      if (m) actualizado = iso(m[3], m[1], m[2]);
    } else if (actual && esProducto(l, perim)) {
      if (tabla) {                                               // fila: producto, versiones afectadas, solución
        poner(estado, l, (ls[i + 1] || '').toLowerCase().startsWith('not affected') ? 'no afectado' : 'afectado');
        i += 3; continue;
      }
      poner(estado, l, actual);
    }
    i++;
  }
  return { version: null, nota, estado, actualizado };
}

function paloalto(datos, perim) {
  const cna = (datos.containers || {}).cna || {};
  const estado = {};
  for (const a of cna.affected || []) {
    const producto = (a.product || '').replace(/\s+/g, ' ').trim();
    if (!new RegExp(perim).test(producto.toLowerCase())) continue;
    const st = (a.versions || []).map(v => v.status);
    poner(estado, producto, st.includes('affected') ? 'afectado'
      : [...st, a.defaultStatus].includes('unknown') ? 'investigando' : 'no afectado');
  }
  const tl = [...(cna.timeline || [])].sort((x, y) => (x.time || '').localeCompare(y.time || ''));
  const ult = tl[tl.length - 1];
  const d = ult && new Date(ult.time);
  return { version: null, nota: ult ? ult.value || '' : '', estado,
    actualizado: d && !isNaN(d) ? d.toISOString().replace(/\.\d{3}Z$/, 'Z') : null };
}

// estado de los productos perimetrales en un aviso vivo, o null si no se ha podido leer
const detalle = async (url, tipo, perim) => {
  try {
    if (tipo === 'paloalto') {
      const datos = await this.helpers.httpRequest({ url: url.replace(/(paloaltonetworks\.com)\//, '$1/json/'), json: true });
      return paloalto(typeof datos === 'string' ? JSON.parse(datos) : datos, perim);
    }
    const pagina = await this.helpers.httpRequest({ url, headers: { 'User-Agent': 'Mozilla/5.0 (informe-vulns; radar n8n)' }, json: false });
    return (tipo === 'cisco' ? cisco : fortinet)(lineas(String(pagina)), perim);
  } catch (e) { return null; }                                   // se vuelve a intentar en la siguiente ejecución
};

// [[producto, antes, ahora]] entre dos lecturas (null = no aparece). Lectura nueva vacía = página cambiada: nada
function cambios(antes, ahora) {
  if (!ahora || !Object.keys(ahora).length) return [];
  const orden = c => ESTADOS.includes(c[2]) ? ESTADOS.indexOf(c[2]) : ESTADOS.length;
  return [...new Set([...Object.keys(antes), ...Object.keys(ahora)])]
    .filter(p => (antes[p] ?? null) !== (ahora[p] ?? null))
    .map(p => [p, antes[p] ?? null, ahora[p] ?? null])
    .sort((a, b) => orden(a) - orden(b) || (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));   // afectados primero
}

// se leen los del periodo de seguimiento (avisos vivos), pero solo son nuevos los de los últimos dias_aviso.
// Sin «seguimiento» en boletines.json (rama main sin actualizar) el radar funciona como antes, sin detalle.
const seg = conf.seguimiento || { dias: 0, perimetrales: {} };
const dias = cfg.probar ? 60 : Math.max(conf.dias_aviso, seg.dias);
const corte = new Date(Date.now() - dias * 864e5).toISOString();
const corteAviso = new Date(Date.now() - conf.dias_aviso * 864e5).toISOString();
const vistos = new Set(), bols = [];
for (const feed of conf.feeds) {
  let entradas;
  try {
    const xml = await this.helpers.httpRequest({ url: feed.url, headers: { 'User-Agent': 'Mozilla/5.0 (informe-vulns; radar n8n)' }, json: false });
    entradas = leerFeed(String(xml));
  } catch (e) { continue; }                                    // un feed caído no para los demás
  for (const e of entradas) {
    const clase = clasificar(e.titulo, feed.tipo, conf.reglas);
    if (!clase || !e.fecha || e.fecha < corte || vistos.has(e.id)) continue;
    if (feed.productos && !new RegExp(feed.productos).test(e.titulo.toLowerCase())) continue;
    vistos.add(e.id);
    const b = { id: e.id, fabricante: NOMBRES[feed.fabricante] || feed.fabricante, fuente: feed.fuente,
      etiqueta: conf.etiquetas[clase], titulo: e.titulo, url: e.url, fecha: e.fecha,
      cves: [...new Set(((e.titulo + ' ' + e.resumen).match(/CVE-\d{4}-\d{4,}/gi) || []).map(c => c.toUpperCase()))].sort() };
    if (clase === 'terceros' && feed.detalle && seg.perimetrales[feed.detalle])
      b.detalle = await detalle(e.url, feed.detalle, seg.perimetrales[feed.detalle]);
    bols.push(b);
  }
}
bols.sort((a, b) => b.fecha.localeCompare(a.fecha));

// huellas: última lectura de cada aviso vivo (producto → estado). La primera de un aviso ya avisado solo se guarda.
const conEstado = bols.filter(b => b.detalle && Object.keys(b.detalle.estado).length);
const huellas = { ...(estado.huellas || {}) };
for (const b of conEstado) huellas[b.id] = b.detalle.estado;

let nuevos, cambiados;
if (cfg.probar) {
  nuevos = bols.slice(0, 3);
  // y un aviso vivo «actualizado», como si antes todos sus productos hubieran estado en investigación
  cambiados = conEstado
    .map(b => ({ ...b, cambios: cambios(Object.fromEntries(Object.keys(b.detalle.estado).map(p => [p, 'investigando'])), b.detalle.estado) }))
    .filter(b => b.cambios.length).slice(0, 1);
} else {
  if (!estado.boletines) {
    estado.boletines = {};
    const ahora = new Date().toISOString();
    for (const b of bols) estado.boletines[b.id] = ahora;
    estado.huellas = huellas;
    return [];
  }
  nuevos = bols.filter(b => !(b.id in estado.boletines) && b.fecha >= corteAviso);
  const idsNuevos = new Set(nuevos.map(b => b.id));
  cambiados = conEstado
    .filter(b => !idsNuevos.has(b.id) && estado.huellas && b.id in estado.huellas)
    .map(b => ({ ...b, cambios: cambios(estado.huellas[b.id], b.detalle.estado) }))
    .filter(b => b.cambios.length);
  if (!nuevos.length && !cambiados.length) {
    // sin correo: las primeras lecturas se guardan ya (las huellas de avisos olvidados se descartan)
    estado.huellas = Object.fromEntries(Object.entries(huellas).filter(([id]) => id in estado.boletines));
    return [];
  }
}
if (!nuevos.length && !cambiados.length) return [];

// Correo: el mismo que monta avisos.py (html_boletines). Compatible con Outlook de escritorio: solo tablas de
// ancho fijo y estilos en línea; nada de margin, padding ni max-width en div o span.
const FUENTE = "font-family:'Segoe UI',Helvetica,Arial,sans-serif;";
const SERIF = "font-family:Georgia,'Times New Roman',serif;";
const MESES = ['ene', 'feb', 'mar', 'abr', 'may', 'jun', 'jul', 'ago', 'sep', 'oct', 'nov', 'dic'];
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const fechaCorta = iso => `${Number(iso.slice(8, 10))} ${MESES[Number(iso.slice(5, 7)) - 1]} ${iso.slice(0, 4)}`;
const listaCves = c => c.slice(0, 6).join(', ') + (c.length > 6 ? ` y ${c.length - 6} más` : '');
const ESTADO_ES = { 'afectado': 'afectado', 'investigando': 'en investigación', 'no afectado': 'no afectado', null: 'sin mención' };
const ESTADO_COLOR = { 'afectado': '#C8102E', 'investigando': '#C55A11', 'no afectado': '#374151', null: '#6b7280' };
const ESTADO_GRUPO = { 'afectado': 'Afectados', 'investigando': 'En investigación', 'no afectado': 'No afectados' };
const revision = d => [d && d.actualizado ? fechaCorta(d.actualizado) : null, d && d.version ? `v${d.version}` : null].filter(Boolean).join(' · ');
const fila = contenido => `<tr><td style="${FUENTE}font-size:13px;line-height:19px;color:#374151;padding-top:6px;">${contenido}</td></tr>`;
// productos perimetrales por estado (avisos vivos nuevos)
const htmlEstado = b => !b.detalle ? '' : ESTADOS
  .map(est => [est, Object.keys(b.detalle.estado).filter(p => b.detalle.estado[p] === est)]).filter(([, p]) => p.length)
  .map(([est, p]) => fila(`<span style="font-weight:bold;color:${ESTADO_COLOR[est]};">${ESTADO_GRUPO[est]}:</span> ${esc(p.join(', '))}`)).join('');
// nota de la revisión y una fila por producto que ha cambiado de estado
const htmlCambios = b => (b.detalle.nota ? `<tr><td style="${FUENTE}font-size:13px;line-height:19px;color:#6b7280;font-style:italic;padding-top:6px;">${esc(b.detalle.nota)}</td></tr>` : '')
  + b.cambios.map(([p, antes, ahora]) => fila(`<span style="font-weight:bold;">${esc(p)}</span>: <span style="color:${ESTADO_COLOR[antes]};">${ESTADO_ES[antes]}</span> &rarr; <span style="font-weight:bold;color:${ESTADO_COLOR[ahora]};">${ESTADO_ES[ahora]}</span>`)).join('');

const grupos = {};
for (const b of nuevos) (grupos[b.fabricante] ??= []).push([b, false]);
for (const b of cambiados) (grupos[b.fabricante] ??= []).push([b, true]);
let bloques = '';
Object.entries(grupos).forEach(([fab, lista], nf) => {
  bloques += `
        <tr><td colspan="2" style="${SERIF}font-size:26px;line-height:32px;color:#111827;padding:${nf ? 32 : 8}px 0 4px 0;">${esc(fab)}</td></tr>`;
  lista.forEach(([b, cambiado], i) => {
    const cves = b.cves.length && !cambiado ? fila(`CVEs: ${esc(listaCves(b.cves))}`) : '';
    const [etiqueta, cuando] = cambiado ? ['Actualizado', revision(b.detalle)] : [b.etiqueta, fechaCorta(b.fecha)];
    bloques += `
        <tr><td colspan="2" style="${FUENTE}${i ? 'border-top:1px solid #e5e7eb;' : ''}padding:14px 0;">
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
            <tr><td style="${FUENTE}font-size:10px;line-height:16px;font-weight:bold;letter-spacing:1px;text-transform:uppercase;color:#C55A11;">${esc(etiqueta)}<span style="font-weight:normal;color:#6b7280;">&nbsp;&nbsp;·&nbsp;&nbsp;${esc(cuando)}&nbsp;&nbsp;·&nbsp;&nbsp;${esc(b.fuente)}</span></td></tr>
            <tr><td style="${FUENTE}font-size:15px;line-height:22px;padding-top:4px;"><a href="${esc(b.url)}" style="color:#111827;font-weight:bold;text-decoration:none;"><span style="color:#111827;">${esc(b.titulo)}</span></a></td></tr>
            ${cves}${cambiado ? htmlCambios(b) : htmlEstado(b)}
          </table>
        </td></tr>`;
  });
});
const boton = cfg.informe_url ? `
        <tr><td colspan="2" style="padding-top:28px;">
          <table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>
            <td bgcolor="#111827" style="background-color:#111827;border-radius:20px;padding:11px 20px;${FUENTE}">
              <a href="${esc(cfg.informe_url)}" style="color:#ffffff;font-size:14px;text-decoration:none;font-weight:bold;"><span style="color:#ffffff;">Ver el informe completo</span></a>
            </td></tr></table>
        </td></tr>` : '';
const n = nuevos.length, m = cambiados.length;
const titulo = [n ? `${n} aviso${n !== 1 ? 's' : ''} de fabricante` : '',
  m ? `${m} aviso${m !== 1 ? 's' : ''} actualizado${m !== 1 ? 's' : ''}` : ''].filter(Boolean).join(' y ');
const html = `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background-color:#f3f4f6;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="#f3f4f6" style="background-color:#f3f4f6;">
  <tr><td align="center" style="padding:24px 12px;">
    <table role="presentation" width="640" cellpadding="0" cellspacing="0" border="0" bgcolor="#ffffff" style="width:640px;max-width:640px;background-color:#ffffff;border:1px solid #e5e7eb;">
      <tr><td style="padding:28px 32px 4px 32px;${FUENTE}">
        <div style="font-size:11px;letter-spacing:2px;text-transform:uppercase;color:#6b7280;">Seguridad perimetral</div>
        <div style="${SERIF}font-size:32px;line-height:40px;color:#111827;padding-top:6px;padding-bottom:14px;border-bottom:1px solid #111827;">${titulo}</div>
      </td></tr>
      <tr><td style="padding:8px 32px 32px 32px;">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">${bloques}${boton}
        </table>
      </td></tr>
    </table>
    <table role="presentation" width="640" cellpadding="0" cellspacing="0" border="0" style="width:640px;max-width:640px;">
      <tr><td align="center" style="padding-top:12px;${FUENTE}font-size:12px;color:#9ca3af;">Fuentes: feeds oficiales de los fabricantes</td></tr>
    </table>
  </td></tr>
</table>
</body></html>`;

const b0 = [...nuevos, ...cambiados][0];
let asunto;
if (!n && m === 1) {
  const [p, , ahora] = b0.cambios[0], mas = b0.cambios.length > 1 ? ` y ${b0.cambios.length - 1} más` : '';
  asunto = `[Vulns perimetrales] Aviso actualizado de ${b0.fabricante}: ${p} ${ESTADO_ES[ahora]}${mas} — ${b0.titulo}`;
} else if (n === 1 && !m) {
  asunto = `[Vulns perimetrales] Aviso de ${b0.fabricante}: ${b0.titulo}`;
} else {
  asunto = `[Vulns perimetrales] ${titulo} — ${b0.fabricante}: ${b0.titulo}`;
}
// «Marcar como avisados» guarda los ids y las huellas solo si el correo ha salido bien
return [{ json: { de: cfg.de, para: cfg.para, asunto, html, ids: nuevos.map(b => b.id), huellas } }];
