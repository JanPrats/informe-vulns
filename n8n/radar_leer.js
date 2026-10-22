// Nodo «Leer boletines»: lee los feeds oficiales de boletines.json y se queda con lo que NVD no ve
// (hardening sin CVE, preavisos, componentes de terceros). Misma lógica que boletines.py: si cambias una,
// cambia la otra. Devuelve un único elemento con el correo ya montado, o nada si no hay boletines nuevos.
// La primera ejecución activa solo los marca como avisados, sin enviar nada.
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

const dias = cfg.probar ? 60 : conf.dias_aviso;
const corte = new Date(Date.now() - dias * 864e5).toISOString();
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
    bols.push({ id: e.id, fabricante: NOMBRES[feed.fabricante] || feed.fabricante, fuente: feed.fuente,
      etiqueta: conf.etiquetas[clase], titulo: e.titulo, url: e.url, fecha: e.fecha,
      cves: [...new Set(((e.titulo + ' ' + e.resumen).match(/CVE-\d{4}-\d{4,}/gi) || []).map(c => c.toUpperCase()))].sort() });
  }
}
bols.sort((a, b) => b.fecha.localeCompare(a.fecha));

let nuevos;
if (cfg.probar) {
  nuevos = bols.slice(0, 3);
} else {
  if (!estado.boletines) {
    estado.boletines = {};
    const ahora = new Date().toISOString();
    for (const b of bols) estado.boletines[b.id] = ahora;
    return [];
  }
  nuevos = bols.filter(b => !(b.id in estado.boletines));
}
if (!nuevos.length) return [];

// Correo: el mismo que monta avisos.py (html_boletines). Compatible con Outlook de escritorio: solo tablas de
// ancho fijo y estilos en línea; nada de margin, padding ni max-width en div o span.
const FUENTE = "font-family:'Segoe UI',Helvetica,Arial,sans-serif;";
const SERIF = "font-family:Georgia,'Times New Roman',serif;";
const MESES = ['ene', 'feb', 'mar', 'abr', 'may', 'jun', 'jul', 'ago', 'sep', 'oct', 'nov', 'dic'];
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const fechaCorta = iso => `${Number(iso.slice(8, 10))} ${MESES[Number(iso.slice(5, 7)) - 1]} ${iso.slice(0, 4)}`;
const listaCves = c => c.slice(0, 6).join(', ') + (c.length > 6 ? ` y ${c.length - 6} más` : '');

const grupos = {};
for (const b of nuevos) (grupos[b.fabricante] ??= []).push(b);
let bloques = '';
Object.entries(grupos).forEach(([fab, lista], nf) => {
  bloques += `
        <tr><td colspan="2" style="${SERIF}font-size:26px;line-height:32px;color:#111827;padding:${nf ? 32 : 8}px 0 4px 0;">${esc(fab)}</td></tr>`;
  lista.forEach((b, i) => {
    const cves = b.cves.length ? `<tr><td style="${FUENTE}font-size:13px;line-height:19px;color:#374151;padding-top:6px;">CVEs: ${esc(listaCves(b.cves))}</td></tr>` : '';
    bloques += `
        <tr><td colspan="2" style="${FUENTE}${i ? 'border-top:1px solid #e5e7eb;' : ''}padding:14px 0;">
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
            <tr><td style="${FUENTE}font-size:10px;line-height:16px;font-weight:bold;letter-spacing:1px;text-transform:uppercase;color:#C55A11;">${esc(b.etiqueta)}<span style="font-weight:normal;color:#6b7280;">&nbsp;&nbsp;·&nbsp;&nbsp;${fechaCorta(b.fecha)}&nbsp;&nbsp;·&nbsp;&nbsp;${esc(b.fuente)}</span></td></tr>
            <tr><td style="${FUENTE}font-size:15px;line-height:22px;padding-top:4px;"><a href="${esc(b.url)}" style="color:#111827;font-weight:bold;text-decoration:none;"><span style="color:#111827;">${esc(b.titulo)}</span></a></td></tr>
            ${cves}
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
const n = nuevos.length;
const titulo = `${n} aviso${n !== 1 ? 's' : ''} de fabricante`;
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

const b0 = nuevos[0];
const asunto = n === 1
  ? `[Vulns perimetrales] Aviso de ${b0.fabricante}: ${b0.titulo}`
  : `[Vulns perimetrales] ${n} avisos de fabricante — ${b0.fabricante}: ${b0.titulo}`;
return [{ json: { de: cfg.de, para: cfg.para, asunto, html, ids: nuevos.map(b => b.id) } }];
