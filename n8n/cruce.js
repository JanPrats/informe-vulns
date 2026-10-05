// Nodo «Cruzar con clientes»: compara las CVEs nuevas con el Excel de clientes y monta el correo.
// Entrada: una fila por equipo del Excel (Cliente | Fabricante | Producto | Versión).
// Misma lógica que «¿Me afecta?» de la web. Estados de cada equipo afectado:
//   explotable -> versión afectada y la CVE no exige ninguna configuración especial
//   revisar    -> versión afectada, pero solo es explotable con cierta configuración (se indica cuál)
//   version    -> el producto coincide, pero no se puede determinar si su versión está afectada

const cfg = $('Configuración').first().json;
const { nuevas, feed } = $('CVEs sin avisar').first().json;
const EQUIV = feed.equivalencias || {};
const P = feed.plantillas;

// ----------------------------------------------------------------------------- inventario
const clave = t => String(t ?? '').normalize('NFD').replace(/[̀-ͯ]/g, '').trim().toLowerCase();
const inventario = [];
for (const item of $input.all()) {
  const fila = {};
  for (const [k, v] of Object.entries(item.json)) fila[clave(k)] = String(v ?? '').trim();
  const eq = { cliente: fila.cliente, fabricante: fila.fabricante, producto: fila.producto, version: fila.version };
  if (eq.cliente && eq.fabricante && eq.producto && eq.version) inventario.push(eq);
}
if (!inventario.length) {
  throw new Error('El Excel no tiene filas válidas. La primera fila debe ser: Cliente | Fabricante | Producto | Versión');
}

// ----------------------------------------------------------------------------- versiones
// «3.2.0 p7» = «3.2 Patch 7», «3.4.0» = «3.4», «14.1-73.37» = [14,1,73,37]
const RE_PARCHE = /^(.*?)(?:^|[\s._-])p(?:atch)?\s*\.?\s*(\d+)\b/i;
const digitos = t => (String(t).match(/\d+/g) || []).map(Number);

function numeros(t) {
  t = String(t);
  const m = t.match(RE_PARCHE);
  let base, parche;
  if (m && /\d/.test(m[1])) { base = digitos(m[1]); parche = [Number(m[2])]; }
  else { base = digitos(t); parche = []; }
  while (base.length > 1 && base[base.length - 1] === 0) base.pop();
  return base.concat(parche);
}

function comparar(a, b) {
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const x = i < a.length ? a[i] : -1, y = i < b.length ? b[i] : -1;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

function rango(t) {
  let m;
  if ((m = t.match(/^(.+?)\s*→\s*anteriores a (.+)$/i))) return { ini: m[1], fin: m[2], incl: false };
  if ((m = t.match(/^anteriores a (.+)$/i))) return { fin: m[1], incl: false };
  if ((m = t.match(/^(.+?)\s*→\s*(.+?) \(incluida\)$/i))) return { ini: m[1], fin: m[2], incl: true };
  if ((m = t.match(/^hasta (.+?) \(incluida\)$/i))) return { fin: m[1], incl: true };
  if (/^todas$/i.test(t)) return { todas: true };
  return { exacta: t };
}

const ramaDe = t => (String(t).match(/\d+/g) || []).slice(0, 2).join('.');

function arregloRama(r, rama) {
  for (const f of r.arreglos || []) if (/^\d/.test(f.rama) && ramaDe(f.rama) === rama) return f.corregida;
  return null;
}

// ----------------------------------------------------------------------------- productos
const norm = t => String(t ?? '').toLowerCase().replace(/\s+/g, ' ').trim();

function clavesProducto(producto) {
  const p = norm(producto), claves = new Set([p]);
  for (const [k, v] of Object.entries(EQUIV)) if (p.includes(k)) v.forEach(x => claves.add(x));
  return claves;
}

function coincideProducto(prodInventario, prodCve) {
  const pc = norm(prodCve);
  if (!pc) return false;
  return [...clavesProducto(prodInventario)].some(c => c && (pc.includes(c) || norm(prodInventario).includes(pc)));
}

function coincideFabricante(a, b) {
  a = norm(a); b = norm(b);
  return !!a && !!b && (b.includes(a) || a.includes(b));
}

// ----------------------------------------------------------------------------- comparación
// [afectada: true | false | null (no se puede determinar), versión a la que actualizar]
function versionAfectada(r, filas, version) {
  const v = numeros(version);
  if (!v.length) return [null, null];
  const esLista = filas.every(f => 'exacta' in rango(f.afectadas));
  const coinciden = [];
  for (const f of filas) {
    const g = rango(f.afectadas);
    let dentro;
    if (g.todas) dentro = true;
    else if ('exacta' in g) dentro = comparar(v, numeros(g.exacta)) === 0;
    else {
      const sobre = !g.ini || comparar(v, numeros(g.ini)) >= 0;
      const c = comparar(v, numeros(g.fin));
      dentro = sobre && (g.incl ? c <= 0 : c < 0);
    }
    if (dentro) {
      const fin = numeros(g.fin || g.exacta || '');
      let comun = 0;
      while (comun < v.length && comun < fin.length && v[comun] === fin[comun]) comun++;
      coinciden.push([comun, f]);
    }
  }
  const delAviso = arregloRama(r, ramaDe(version));
  if (coinciden.length) {
    coinciden.sort((x, y) => y[0] - x[0]);
    return [true, delAviso && /^\d/.test(delAviso) ? delAviso : coinciden[0][1].corregida];
  }
  if (delAviso && /^\d/.test(delAviso) && comparar(v, numeros(delAviso)) >= 0) return [false, null];
  // con una lista de versiones sueltas no se puede afirmar «no afectada» si la rama aparece en la lista
  if (esLista && filas.some(f => ramaDe(f.afectadas) === ramaDe(version))) return [null, null];
  return [false, null];
}

const ORDEN = { explotable: 0, revisar: 1, version: 2 };

function afectados(r) {
  const salida = [], condiciones = r.condiciones_explotacion || [];
  for (const eq of inventario) {
    if (!coincideFabricante(eq.fabricante, r.fabricante)) continue;
    const filas = (r.versiones || []).filter(f => coincideProducto(eq.producto, f.producto));
    if (!filas.length) {
      // sin tabla de versiones de ese producto: solo se avisa si el producto aparece en la CVE
      const texto = norm(`${r.producto || ''} ${r.descripcion || ''}`);
      if (!(r.versiones || []).length && [...clavesProducto(eq.producto)].some(c => texto.includes(c))) {
        salida.push({ ...eq, estado: 'version', arreglo: null, condiciones });
      }
      continue;
    }
    const [afectada, arreglo] = versionAfectada(r, filas, eq.version);
    if (afectada === null) salida.push({ ...eq, estado: 'version', arreglo: null, condiciones });
    else if (afectada) salida.push({ ...eq, estado: condiciones.length ? 'revisar' : 'explotable', arreglo, condiciones });
  }
  return salida.sort((a, b) => ORDEN[a.estado] - ORDEN[b.estado] || a.cliente.localeCompare(b.cliente, 'es'));
}

// ----------------------------------------------------------------------------- correo
const FUENTE = "font-family:'Segoe UI',Helvetica,Arial,sans-serif;";
const ESTADOS = {
  explotable: ['Vulnerable y explotable', '#dc2626'],
  revisar: ['Vulnerable por versión · revisar si es explotable', '#c2410c'],
  version: ['Revisar versión', '#6b7280'],
};
const esc = s => String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;').replace(/'/g, '&#x27;');
const rellenar = (plantilla, valores) => Object.entries(valores).reduce((h, [k, v]) => h.split(k).join(v), plantilla);

function htmlClientes(equipos) {
  const titulo = `<tr><td style="${FUENTE}font-size:13px;line-height:19px;font-weight:bold;color:#111827;padding-top:12px;">Clientes afectados:</td></tr>`;
  if (!equipos.length) {
    return titulo + `<tr><td style="${FUENTE}font-size:13px;line-height:19px;color:#6b7280;padding:2px 0 0 14px;">&bull;&nbsp;Ninguno</td></tr>`;
  }
  return titulo + equipos.map(eq => {
    const [etiqueta, color] = ESTADOS[eq.estado];
    let detalle = '';
    if (eq.estado === 'revisar' && eq.condiciones.length) {
      detalle = `<br><span style="color:#6b7280;">Solo explotable si: ${esc(eq.condiciones.join(' / '))}</span>`;
    } else if (eq.estado === 'version') {
      detalle = '<br><span style="color:#6b7280;">No se puede determinar si esta versión está afectada: confírmalo en el aviso.</span>';
    }
    const arreglo = eq.arreglo && eq.arreglo !== 'Consultar aviso'
      ? ` &rarr; actualizar a <b style="color:#111827;">${esc(eq.arreglo)}</b>` : '';
    return `<tr><td style="${FUENTE}font-size:13px;line-height:19px;color:#374151;padding:4px 0 0 14px;">`
      + `&bull;&nbsp;<b style="color:#111827;">${esc(eq.cliente)}</b> · ${esc(eq.producto)} ${esc(eq.version)}`
      + ` &mdash; <b style="color:${color};">${esc(etiqueta)}</b>${arreglo}${detalle}</td></tr>`;
  }).join('');
}

const prioridad = r => (r.explotada_kev ? 100 : 0) + (r.cvss || 0);

// Igual que la web: fabricante → producto → CVEs, todo ordenado por gravedad (explotadas primero)
function agrupar(lista) {
  const grupos = new Map();
  for (const r of lista) {
    if (!grupos.has(r.fabricante)) grupos.set(r.fabricante, new Map());
    const prods = grupos.get(r.fabricante);
    if (!prods.has(r.producto)) prods.set(r.producto, []);
    prods.get(r.producto).push(r);
  }
  const salida = [...grupos].map(([fab, prods]) => {
    const l = [...prods].map(([p, rs]) => [p, [...rs].sort((a, b) => prioridad(b) - prioridad(a))]);
    l.sort((a, b) => prioridad(b[1][0]) - prioridad(a[1][0]));
    return [fab, l];
  });
  const total = x => x[1].reduce((s, [, rs]) => s + rs.length, 0);
  salida.sort((a, b) => prioridad(b[1][0][1][0]) - prioridad(a[1][0][1][0]) || total(b) - total(a));
  return salida;
}

const porCve = new Map(nuevas.map(r => [r.cve, afectados(r)]));
const conClientes = nuevas.filter(r => porCve.get(r.cve).length);
const lista = cfg.solo_con_afectados ? conClientes : nuevas;
const ids = nuevas.map(r => r.cve);

if (!lista.length) {
  // ninguna afecta a clientes y solo se quiere aviso cuando afectan: se marcan como avisadas sin enviar nada
  if (!cfg.probar) {
    const estado = $getWorkflowStaticData('global');
    const ahora = new Date().toISOString();
    for (const id of ids) estado.avisadas[id] = ahora;
  }
  return [];
}

const bloques = [];
agrupar(lista).forEach(([fab, prods], nf) => {
  bloques.push(rellenar(nf === 0 ? P.fabricante_primero : P.fabricante, { '@@FABRICANTE@@': esc(fab) }));
  for (const [prod, rs] of prods) {
    bloques.push(rellenar(P.producto, { '@@PRODUCTO@@': esc(prod), '@@CUENTA@@': `${rs.length} CVE${rs.length !== 1 ? 'S' : ''}` }));
    rs.forEach((r, i) => bloques.push(rellenar(r.html, {
      '@@BORDE@@': i ? 'border-top:1px solid #e5e7eb;' : '',
      '<!--CLIENTES-->': htmlClientes(porCve.get(r.cve)),
    })));
  }
});

const n = lista.length;
const clientes = new Set(conClientes.flatMap(r => porCve.get(r.cve).map(eq => eq.cliente)));
const titulo = `${n} vulnerabilidad${n !== 1 ? 'es' : ''} nueva${n !== 1 ? 's' : ''}`;
const html = rellenar(P.pagina, { '@@TITULO@@': esc(titulo), '@@BLOQUES@@': bloques.join('') });

const peor = lista.reduce((a, b) => (prioridad(b) > prioridad(a) ? b : a));
const explotadas = lista.filter(r => r.explotada_kev).length;
const asunto = `[Vulns clientes] ${n} CVE${n !== 1 ? 's nuevas' : ' nueva'}`
  + (explotadas ? ` · ${explotadas} explotada${explotadas > 1 ? 's' : ''}` : '')
  + ` · ${clientes.size ? `${clientes.size} cliente${clientes.size > 1 ? 's' : ''} afectado${clientes.size > 1 ? 's' : ''}` : 'ningún cliente afectado'}`
  + ` — ${peor.fabricante} ${peor.cve}` + (peor.cvss != null ? ` (${peor.cvss.toFixed(1)})` : '');

return [{ json: { de: cfg.de, para: cfg.para, asunto, html, ids, clientes_afectados: clientes.size } }];
