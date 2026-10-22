#!/usr/bin/env python3
"""
Avisos por correo de CVEs nuevas en productos de seguridad perimetral.

Pensado para ejecutarse cada 15 minutos (GitHub Actions). En cada ejecución:
  1. Descarga de NVD lo publicado en los últimos días (con caché incremental).
  2. Se queda con las CVEs de los fabricantes vigilados (los mismos que el informe).
  3. Guarda novedades.json con esas CVEs (versiones, arreglos, condiciones de explotación y el bloque del
     correo ya montado). Lo lee n8n, que lo cruza con el inventario de clientes fuera de GitHub.
  4. Si hay alguna que todavía no se haya avisado, envía UN correo con todas ellas (sin clientes: es el
     aviso de respaldo).

La primera ejecución no envía nada: solo marca como «ya avisadas» las CVEs actuales,
para no recibir de golpe todo lo de los últimos días.

Configuración (variables de entorno; en GitHub, como secretos):
  SMTP_USER       cuenta que envía (p. ej. una cuenta de Gmail)
  SMTP_PASSWORD   contraseña de aplicación de esa cuenta
  AVISO_PARA      dirección que recibe los avisos (si falta, se usa SMTP_USER)
  SMTP_HOST       por defecto smtp.gmail.com
  SMTP_PORT       por defecto 465 (SSL)
  INFORME_URL     enlace al informe web que se incluye en el correo
  AVISO_FABRICANTES  opcional: solo avisar de estos fabricantes, separados por comas
                     (clave o nombre, p. ej. "fortinet,paloalto" o "Fortinet,Palo Alto Networks")
  NVD_API_KEY     opcional

Uso:
  python avisos.py              # comprueba y avisa si hay novedades
  python avisos.py --probar     # envía ya un correo de prueba con las 3 CVEs más recientes
  python avisos.py --vista-previa correo.html   # igual, pero solo guarda el correo en un HTML
"""
import argparse
import html
import json
import os
import smtplib
import ssl
import sys
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage

import afectacion
import boletines
import vulns_perimetrales as vp

CARPETA = os.path.dirname(os.path.abspath(__file__))
RUTA_ESTADO = os.path.join(CARPETA, ".estado_avisos.json")
RUTA_CACHE_NVD = os.path.join(CARPETA, ".cache_nvd_avisos.json")
RUTA_CACHE_CNA = os.path.join(CARPETA, ".cache_cna.json")
RUTA_CACHE_AVISOS = os.path.join(CARPETA, ".cache_avisos.json")
RUTA_NOVEDADES = os.path.join(CARPETA, "novedades.json")
VENTANA_DIAS = 3          # se revisa lo publicado en los últimos 3 días (NVD a veces indexa con retraso)
RECUERDA_DIAS = 30        # cuánto tiempo se recuerda que una CVE ya se avisó
SEV_ES = {"CRITICAL": "Crítica", "HIGH": "Alta", "MEDIUM": "Media", "LOW": "Baja"}
SEV_COLOR = {"CRITICAL": "#86198f", "HIGH": "#c2410c", "MEDIUM": "#a16207", "LOW": "#3f6212"}

# Huecos de las plantillas del correo. n8n los rellena igual que este script (ver n8n/cruce.js).
BORDE = "@@BORDE@@"              # separador con la CVE anterior del mismo producto
CLIENTES = "<!--CLIENTES-->"     # aquí n8n inserta los clientes afectados por la CVE
FUENTE = "font-family:'Segoe UI',Helvetica,Arial,sans-serif;"
SERIF = "font-family:Georgia,'Times New Roman',serif;"


def cves_del_historico(ids, url):
    """Para las pruebas: toma CVEs concretas del histórico (archivo.js local o el publicado en la web)."""
    import urllib.request
    local = os.path.join(CARPETA, "archivo.js")
    if os.path.exists(local):
        with open(local, encoding="utf-8") as f:
            texto = f.read()
    else:
        with urllib.request.urlopen(url.rstrip("/") + "/archivo.js", timeout=60) as r:
            texto = r.read().decode("utf-8")
    datos = json.loads(texto[texto.index("=") + 1:texto.rstrip().rstrip(";").rindex("}") + 1])["data"]
    por_cve = {r["cve"]: r for r in datos}
    return [por_cve[i] for i in ids if i in por_cve]


def cargar_estado():
    try:
        with open(RUTA_ESTADO, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def guardar_estado(avisadas, bols):
    """CVEs y boletines ya avisados, en el mismo archivo (así no cambia la lista de la caché de Actions)."""
    with open(RUTA_ESTADO, "w", encoding="utf-8") as f:
        json.dump({"avisadas": avisadas, "boletines": bols}, f)


# ----------------------------------------------------------------------------- correo

def asunto(nuevas):
    n = len(nuevas)
    explotadas = sum(1 for r in nuevas if r["explotada_kev"])
    peor = max(nuevas, key=lambda r: (bool(r["explotada_kev"]), r["cvss"] or 0))
    texto = f"{n} CVE nueva" if n == 1 else f"{n} CVEs nuevas"
    extra = f" · {explotadas} explotada{'s' if explotadas > 1 else ''}" if explotadas else ""
    detalle = f"{peor['fabricante']} {peor['cve']}" + (f" ({peor['cvss']:.1f})" if peor["cvss"] is not None else "")
    return f"[Vulns perimetrales] {texto}{extra} — {detalle}"


def versiones_arreglo(r):
    """Versiones a las que actualizar (sin las entradas genéricas tipo «Consultar aviso»)."""
    return sorted({v["corregida"] for v in r["versiones"] if v["corregida"] != "Consultar aviso"})


def vp_extracto(texto, maximo=220):
    t = " ".join(texto.split())
    primera = t.split(". ")[0]
    primera = primera if primera.endswith(".") else primera + "."
    return primera if len(primera) <= maximo else primera[: maximo - 1] + "…"


def prioridad(r):
    return (100 if r["explotada_kev"] else 0) + (r["cvss"] or 0)


def agrupar(nuevas):
    """Igual que la web: fabricante → producto → CVEs, todo ordenado por gravedad (explotadas primero)."""
    grupos = {}
    for r in nuevas:
        grupos.setdefault(r["fabricante"], {}).setdefault(r["producto"], []).append(r)
    salida = []
    for fab, prods in grupos.items():
        lista = [(p, sorted(rs, key=prioridad, reverse=True)) for p, rs in prods.items()]
        lista.sort(key=lambda x: prioridad(x[1][0]), reverse=True)
        salida.append((fab, lista))
    salida.sort(key=lambda x: (prioridad(x[1][0][1][0]), sum(len(rs) for _, rs in x[1])), reverse=True)
    return salida


def cuerpo_texto(nuevas, url):
    lineas = [f"Se han publicado {len(nuevas)} vulnerabilidades nuevas en productos perimetrales.", ""]
    for fab, prods in agrupar(nuevas):
        lineas += [fab.upper(), "=" * len(fab), ""]
        for prod, rs in prods:
            lineas += [prod, "-" * len(prod)]
            for r in rs:
                score = f"{r['cvss']:.1f}" if r["cvss"] is not None else "sin puntuar"
                lineas.append(f"* {r['cve']} · CVSS {score}" + ("  [EXPLOTADA - CISA KEV]" if r["explotada_kev"] else ""))
                lineas.append(f"  {vp_extracto(r['descripcion'])}")
                if versiones_arreglo(r):
                    lineas.append("  Actualizar a: " + ", ".join(versiones_arreglo(r)))
                lineas.append(f"  {r['url']}")
            lineas.append("")
    if url:
        lineas.append(f"Informe completo: {url}")
    return "\n".join(lineas)


# Piezas del correo HTML. Compatibles con Outlook de escritorio (motor de Word): solo tablas de ancho fijo,
# estilos en línea en cada celda y botón hecho con una celda de color. Nada de max-width, margin ni padding
# en <div>/<span>. Misma organización que la web: fabricante → producto → CVEs.

def html_fabricante(fab, primero):
    return f"""
        <tr><td colspan="2" style="{SERIF}font-size:26px;line-height:32px;color:#111827;padding:{'8' if primero else '32'}px 0 4px 0;">{html.escape(fab)}</td></tr>"""


def html_producto(prod, cuenta):
    """Producto, con una línea debajo como en la web. «cuenta» es el texto «3 CVES»."""
    return f"""
        <tr><td colspan="2" style="{FUENTE}font-size:15px;line-height:20px;font-weight:bold;color:#111827;padding:14px 0 8px 0;border-bottom:1px solid #111827;">{html.escape(prod)}
          <span style="font-weight:normal;font-size:11px;letter-spacing:1px;color:#6b7280;">&nbsp;&nbsp;{cuenta}</span></td></tr>"""


def cuenta_cves(n):
    return f"{n} CVE{'S' if n != 1 else ''}"


def html_cve(r):
    """Bloque de una CVE, con los huecos BORDE y CLIENTES sin rellenar."""
    e = html.escape
    sev = r["severidad"] if r["severidad"] in SEV_ES else "NONE"
    color = SEV_COLOR.get(sev, "#6b7280")
    score = f"{r['cvss']:.1f}" if r["cvss"] is not None else "&mdash;"
    kev = ('&nbsp;&nbsp;<span style="color:#dc2626;font-size:11px;font-weight:bold;letter-spacing:1px;">'
           '&#9679;&nbsp;EXPLOTADA</span>' if r["explotada_kev"] else "")
    fixes = versiones_arreglo(r)
    fix = (f'<tr><td style="{FUENTE}font-size:13px;line-height:19px;color:#374151;padding-top:8px;">Actualizar a: '
           f'<b style="color:#047857;">{e(", ".join(fixes))}</b></td></tr>') if fixes else ""
    return f"""
        <tr>
          <td width="70" valign="top" style="{FUENTE}{BORDE}padding:16px 0;width:70px;">
            <div style="font-size:22px;font-weight:bold;color:{color};line-height:24px;">{score}</div>
            <div style="font-size:10px;font-weight:bold;letter-spacing:1px;text-transform:uppercase;color:{color};line-height:16px;">{e(SEV_ES.get(sev, 'Sin puntuar'))}</div>
          </td>
          <td valign="top" style="{FUENTE}{BORDE}padding:16px 0;">
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
              <tr><td style="{FUENTE}font-size:15px;line-height:22px;"><a href="{e(r['url'])}" style="color:#111827;font-weight:bold;text-decoration:none;"><span style="color:#111827;">{e(r['cve'])}</span></a>{kev}</td></tr>
              <tr><td style="{FUENTE}font-size:14px;line-height:21px;color:#374151;padding-top:4px;">{e(vp_extracto(r['descripcion']))}</td></tr>
              {fix}
              {CLIENTES}
            </table>
          </td>
        </tr>"""


def html_pagina(titulo, bloques, url, pie="Fuentes: NVD, CVE.org y CISA KEV"):
    boton = f"""
        <tr><td colspan="2" style="padding-top:28px;">
          <table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>
            <td bgcolor="#111827" style="background-color:#111827;border-radius:20px;padding:11px 20px;{FUENTE}">
              <a href="{html.escape(url)}" style="color:#ffffff;font-size:14px;text-decoration:none;font-weight:bold;"><span style="color:#ffffff;">Ver el informe completo</span></a>
            </td></tr></table>
        </td></tr>""" if url else ""
    return f"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background-color:#f3f4f6;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="#f3f4f6" style="background-color:#f3f4f6;">
  <tr><td align="center" style="padding:24px 12px;">
    <table role="presentation" width="640" cellpadding="0" cellspacing="0" border="0" bgcolor="#ffffff"
           style="width:640px;max-width:640px;background-color:#ffffff;border:1px solid #e5e7eb;">
      <tr><td style="padding:28px 32px 4px 32px;{FUENTE}">
        <div style="font-size:11px;letter-spacing:2px;text-transform:uppercase;color:#6b7280;">Seguridad perimetral</div>
        <div style="{SERIF}font-size:32px;line-height:40px;color:#111827;padding-top:6px;padding-bottom:14px;border-bottom:1px solid #111827;">{titulo}</div>
      </td></tr>
      <tr><td style="padding:8px 32px 32px 32px;">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">{bloques}{boton}
        </table>
      </td></tr>
    </table>
    <table role="presentation" width="640" cellpadding="0" cellspacing="0" border="0" style="width:640px;max-width:640px;">
      <tr><td align="center" style="padding-top:12px;{FUENTE}font-size:12px;color:#9ca3af;">{pie}</td></tr>
    </table>
  </td></tr>
</table>
</body></html>"""


def cuerpo_html(nuevas, url):
    bloques = []
    for nf, (fab, prods) in enumerate(agrupar(nuevas)):
        bloques.append(html_fabricante(fab, nf == 0))
        for prod, rs in prods:
            bloques.append(html_producto(prod, cuenta_cves(len(rs))))
            for i, r in enumerate(rs):
                bloques.append(html_cve(r).replace(BORDE, "border-top:1px solid #e5e7eb;" if i else "").replace(CLIENTES, ""))
    n = len(nuevas)
    titulo = f"{n} vulnerabilidad{'es' if n != 1 else ''} nueva{'s' if n != 1 else ''}"
    return html_pagina(titulo, "".join(bloques), url)


def enviar(nuevas, url):
    _enviar(asunto(nuevas), cuerpo_texto(nuevas, url), cuerpo_html(nuevas, url))
    print(f"Correo enviado con {len(nuevas)} CVE(s).", file=sys.stderr)


def _enviar(titulo, texto, html_):
    usuario = os.environ.get("SMTP_USER")
    clave = os.environ.get("SMTP_PASSWORD")
    if not usuario or not clave:
        sys.exit("Faltan SMTP_USER y/o SMTP_PASSWORD: no se puede enviar el correo.")
    para = os.environ.get("AVISO_PARA") or usuario
    msg = EmailMessage()
    msg["Subject"] = titulo
    msg["From"] = f"Vulns perimetrales <{usuario}>"
    msg["To"] = para
    msg.set_content(texto)
    msg.add_alternative(html_, subtype="html")
    host = os.environ.get("SMTP_HOST", "smtp.gmail.com")
    puerto = int(os.environ.get("SMTP_PORT", "465"))
    with smtplib.SMTP_SSL(host, puerto, context=ssl.create_default_context(), timeout=60) as s:
        s.login(usuario, clave)
        s.send_message(msg)


# ----------------------------------------------------------------------------- boletines de los fabricantes
# Lo que NVD no ve (hardening sin CVE, preavisos, componentes de terceros). Van en un correo aparte, más corto.
# El radar de n8n (n8n/radar_leer.js) envía el mismo correo antes; este es el respaldo.

AMBAR = "#C55A11"
MESES = ("ene", "feb", "mar", "abr", "may", "jun", "jul", "ago", "sep", "oct", "nov", "dic")


def fecha_corta(iso):
    return f"{int(iso[8:10])} {MESES[int(iso[5:7]) - 1]} {iso[:4]}"


def lista_cves(cves, maximo=6):
    return ", ".join(cves[:maximo]) + (f" y {len(cves) - maximo} más" if len(cves) > maximo else "")


def asunto_boletines(bols):
    b = bols[0]
    if len(bols) == 1:
        return f"[Vulns perimetrales] Aviso de {b['fabricante']}: {b['titulo']}"
    return f"[Vulns perimetrales] {len(bols)} avisos de fabricante — {b['fabricante']}: {b['titulo']}"


def texto_boletines(bols, url):
    lineas = ["Avisos de los fabricantes que no llegan por NVD (hardening, preavisos, componentes de terceros).", ""]
    for b in bols:
        lineas.append(f"* {b['fabricante']} · {b['etiqueta']} · {fecha_corta(b['fecha'])}")
        lineas.append(f"  {b['titulo']}")
        if b["cves"]:
            lineas.append(f"  CVEs: {lista_cves(b['cves'])}")
        lineas += [f"  {b['url']}", ""]
    if url:
        lineas.append(f"Informe completo: {url}")
    return "\n".join(lineas)


def html_boletin(b, borde):
    e = html.escape
    cves = (f'<tr><td style="{FUENTE}font-size:13px;line-height:19px;color:#374151;padding-top:6px;">CVEs: '
            f'{e(lista_cves(b["cves"]))}</td></tr>') if b["cves"] else ""
    return f"""
        <tr><td colspan="2" style="{FUENTE}{'border-top:1px solid #e5e7eb;' if borde else ''}padding:14px 0;">
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
            <tr><td style="{FUENTE}font-size:10px;line-height:16px;font-weight:bold;letter-spacing:1px;text-transform:uppercase;color:{AMBAR};">{e(b['etiqueta'])}<span style="font-weight:normal;color:#6b7280;">&nbsp;&nbsp;·&nbsp;&nbsp;{fecha_corta(b['fecha'])}&nbsp;&nbsp;·&nbsp;&nbsp;{e(b['fuente'])}</span></td></tr>
            <tr><td style="{FUENTE}font-size:15px;line-height:22px;padding-top:4px;"><a href="{e(b['url'])}" style="color:#111827;font-weight:bold;text-decoration:none;"><span style="color:#111827;">{e(b['titulo'])}</span></a></td></tr>
            {cves}
          </table>
        </td></tr>"""


def html_boletines(bols, url):
    bloques, grupos = [], {}
    for b in bols:
        grupos.setdefault(b["fabricante"], []).append(b)
    for nf, (fab, lista) in enumerate(grupos.items()):
        bloques.append(html_fabricante(fab, nf == 0))
        bloques += [html_boletin(b, i > 0) for i, b in enumerate(lista)]
    n = len(bols)
    titulo = f"{n} aviso{'s' if n != 1 else ''} de fabricante"
    return html_pagina(titulo, "".join(bloques), url, "Fuentes: feeds oficiales de los fabricantes")


def enviar_boletines(bols, url):
    _enviar(asunto_boletines(bols), texto_boletines(bols, url), html_boletines(bols, url))
    print(f"Correo enviado con {len(bols)} boletín(es).", file=sys.stderr)


def boletines_recientes(seleccion, dias):
    nombres = {k: vp.FABRICANTES[k]["nombre"] for k in seleccion}
    try:
        return boletines.obtener(dias, nombres)
    except Exception as e:  # noqa: BLE001 - el radar nunca debe impedir los avisos de CVEs
        print(f"Aviso: radar de boletines no disponible ({e})", file=sys.stderr)
        return None


# ----------------------------------------------------------------------------- novedades para n8n

CAMPOS_NOVEDADES = ("cve", "fabricante", "producto", "publicado", "cvss", "severidad", "descripcion", "vector",
                    "url", "aviso", "versiones", "arreglos", "epss")


def escribir_novedades(registros, url, ruta=RUTA_NOVEDADES):
    """CVEs de la ventana, con todo lo que n8n necesita para cruzarlas con el inventario de clientes y montar
    el correo. Solo datos públicos de las CVEs: aquí no hay nada de clientes."""
    cves = []
    for r in registros:
        d = {k: r.get(k) for k in CAMPOS_NOVEDADES}
        d["explotada_kev"] = bool(r.get("explotada_kev"))
        d["condiciones_explotacion"] = afectacion.condiciones_explotacion(r)
        d["html"] = html_cve(r)
        cves.append(d)
    datos = {
        "generado": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "ventana_dias": VENTANA_DIAS,
        "informe_url": url,
        "equivalencias": afectacion.EQUIVALENCIAS,
        "plantillas": {
            "fabricante_primero": html_fabricante("@@FABRICANTE@@", True),
            "fabricante": html_fabricante("@@FABRICANTE@@", False),
            "producto": html_producto("@@PRODUCTO@@", "@@CUENTA@@"),
            "pagina": html_pagina("@@TITULO@@", "@@BLOQUES@@", url),
        },
        "cves": cves,
    }
    with open(ruta, "w", encoding="utf-8") as f:
        json.dump(datos, f, ensure_ascii=False, separators=(",", ":"))
    print(f"novedades.json: {len(cves)} CVEs.", file=sys.stderr)


# ----------------------------------------------------------------------------- main

def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    p = argparse.ArgumentParser(description="Avisos por correo de CVEs nuevas en productos perimetrales")
    p.add_argument("--probar", action="store_true", help="envía un correo de prueba con las 3 CVEs más recientes")
    p.add_argument("--vista-previa", metavar="HTML", help="no envía nada: guarda el correo de prueba en este archivo HTML")
    p.add_argument("--cves", metavar="LISTA", help="para la prueba: CVEs concretas del histórico publicado, separadas por comas")
    p.add_argument("--novedades", metavar="JSON", help="para la prueba: guarda las CVEs de la prueba en este novedades.json")
    p.add_argument("--boletines", action="store_true",
                   help="con --probar o --vista-previa: la prueba es con los 3 boletines de fabricante más recientes")
    a = p.parse_args()

    hasta = datetime.now(timezone.utc)
    desde = hasta - timedelta(days=VENTANA_DIAS)
    api_key = os.environ.get("NVD_API_KEY")
    url = os.environ.get("INFORME_URL", "")

    if (a.probar or a.vista_previa) and a.cves:
        prueba = cves_del_historico([c.strip().upper() for c in a.cves.split(",") if c.strip()], url)
        if not prueba:
            sys.exit("No hay CVEs con las que hacer la prueba.")
        terminar_prueba(a, prueba, url)
        return

    filtro = [x.strip().lower() for x in os.environ.get("AVISO_FABRICANTES", "").split(",") if x.strip()]
    seleccion = [k for k, f in vp.FABRICANTES.items() if not filtro or k in filtro or f["nombre"].lower() in filtro]
    if filtro and not seleccion:
        sys.exit(f"AVISO_FABRICANTES no coincide con ningún fabricante: {filtro}")

    if a.boletines and (a.probar or a.vista_previa):
        prueba = (boletines_recientes(seleccion, 60) or [])[:3]
        if not prueba:
            sys.exit("No hay boletines con los que hacer la prueba.")
        if a.vista_previa:
            with open(a.vista_previa, "w", encoding="utf-8") as f:
                f.write(html_boletines(prueba, url))
            print(f"Asunto: {asunto_boletines(prueba)}\nVista previa guardada en {a.vista_previa}", file=sys.stderr)
        else:
            enviar_boletines(prueba, url)
        return

    kev = vp.descargar_kev()
    cves = vp.obtener_cves(desde, hasta, api_key, RUTA_CACHE_NVD, max_dias=VENTANA_DIAS)
    actuales = vp.filtrar(cves, seleccion, kev, 0)
    por_id = {c["id"]: c for c in cves}

    if a.probar or a.vista_previa:
        prueba = sorted(actuales, key=lambda r: r["publicado"], reverse=True)[:3]
        if not prueba:
            sys.exit("No hay CVEs con las que hacer la prueba.")
        vp.enriquecer(prueba, por_id, RUTA_CACHE_CNA)
        vp.anadir_arreglos_fabricante(prueba, RUTA_CACHE_AVISOS)
        terminar_prueba(a, prueba, url)
        return

    # todas las de la ventana van completas a novedades.json (n8n decide qué clientes afectan)
    vp.enriquecer(actuales, por_id, RUTA_CACHE_CNA)
    vp.anadir_arreglos_fabricante(actuales, RUTA_CACHE_AVISOS)   # versiones corregidas por rama (Cisco)
    escribir_novedades(actuales, url)

    estado = cargar_estado()
    ahora = hasta.strftime("%Y-%m-%dT%H:%M:%SZ")
    avisadas = (estado or {}).get("avisadas", {})
    bols = boletines_recientes(seleccion, boletines.cargar_config()["dias_aviso"])

    if estado is None:
        # Primera ejecución: se marca todo lo actual como ya avisado, sin enviar nada
        guardar_estado({r["cve"]: ahora for r in actuales}, {b["id"]: ahora for b in bols or []})
        print(f"Primera ejecución: {len(actuales)} CVEs actuales marcadas como avisadas. No se envía correo.",
              file=sys.stderr)
        return

    # Boletines de fabricante. La primera vez que hay radar solo se marcan los actuales, sin enviar nada.
    bols_avisados = estado.get("boletines")
    if bols is None:
        bols_avisados = bols_avisados or {}
    elif bols_avisados is None:
        bols_avisados = {b["id"]: ahora for b in bols}
        print(f"Radar de boletines activado: {len(bols)} boletines actuales marcados como avisados.", file=sys.stderr)
    else:
        nuevos = [b for b in bols if b["id"] not in bols_avisados]
        if nuevos:
            enviar_boletines(nuevos, url)
            for b in nuevos:
                bols_avisados[b["id"]] = ahora
            # la web solo se publica una vez al día: el workflow la regenera si hay boletines nuevos
            if os.environ.get("GITHUB_OUTPUT"):
                with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as f:
                    f.write("web=1\n")
        else:
            print("Sin boletines nuevos.", file=sys.stderr)

    nuevas = [r for r in actuales if r["cve"] not in avisadas]
    if nuevas:
        nuevas.sort(key=lambda r: (not r["explotada_kev"], -(r["cvss"] or 0)))
        enviar(nuevas, url)
        for r in nuevas:
            avisadas[r["cve"]] = ahora
    else:
        print("Sin CVEs nuevas.", file=sys.stderr)

    # se olvidan las avisadas hace más de RECUERDA_DIAS (ya no pueden volver a aparecer en la ventana)
    limite = (hasta - timedelta(days=RECUERDA_DIAS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    guardar_estado({k: v for k, v in avisadas.items() if v >= limite},
                   {k: v for k, v in bols_avisados.items() if v >= limite})


def terminar_prueba(a, prueba, url):
    if a.novedades:
        escribir_novedades(prueba, url, a.novedades)
    if a.vista_previa:
        with open(a.vista_previa, "w", encoding="utf-8") as f:
            f.write(cuerpo_html(prueba, url))
        print(f"Asunto: {asunto(prueba)}", file=sys.stderr)
        print(f"Vista previa guardada en {a.vista_previa}", file=sys.stderr)
    elif a.probar:
        enviar(prueba, url)


if __name__ == "__main__":
    main()
