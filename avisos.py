#!/usr/bin/env python3
"""
Avisos por correo de CVEs nuevas en productos de seguridad perimetral.

Pensado para ejecutarse cada 15 minutos (GitHub Actions). En cada ejecución:
  1. Descarga de NVD lo publicado en los últimos días (con caché incremental).
  2. Se queda con las CVEs de los fabricantes vigilados (los mismos que el informe).
  3. Si hay alguna que todavía no se haya avisado, envía UN correo con todas ellas.

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
  INVENTARIO_CLIENTES, CLIENTES_NOMBRES  opcionales: inventario de clientes (ver preparar_inventario.py).
                  Si existen, el correo lista debajo los clientes afectados por cada CVE nueva.

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
import vulns_perimetrales as vp

CARPETA = os.path.dirname(os.path.abspath(__file__))
RUTA_ESTADO = os.path.join(CARPETA, ".estado_avisos.json")
RUTA_CACHE_NVD = os.path.join(CARPETA, ".cache_nvd_avisos.json")
RUTA_CACHE_CNA = os.path.join(CARPETA, ".cache_cna.json")
RUTA_CACHE_AVISOS = os.path.join(CARPETA, ".cache_avisos.json")
VENTANA_DIAS = 3          # se revisa lo publicado en los últimos 3 días (NVD a veces indexa con retraso)
RECUERDA_DIAS = 30        # cuánto tiempo se recuerda que una CVE ya se avisó
SEV_ES = {"CRITICAL": "Crítica", "HIGH": "Alta", "MEDIUM": "Media", "LOW": "Baja"}
SEV_COLOR = {"CRITICAL": "#86198f", "HIGH": "#c2410c", "MEDIUM": "#a16207", "LOW": "#3f6212"}


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


def guardar_estado(avisadas):
    with open(RUTA_ESTADO, "w", encoding="utf-8") as f:
        json.dump({"avisadas": avisadas}, f)


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


def cuerpo_texto(nuevas, url, afect=None):
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
    lineas += texto_clientes(nuevas, afect)
    if url:
        lineas.append(f"Informe completo: {url}")
    return "\n".join(lineas)


def cuerpo_html(nuevas, url, afect=None):
    """HTML compatible con Outlook de escritorio (motor de Word): solo tablas de ancho fijo, estilos en
    línea en cada celda y botón hecho con una celda de color. Nada de max-width, margin ni padding en <div>/<span>.
    Misma organización que la web: fabricante → producto → CVEs."""
    e = html.escape
    fuente = "font-family:'Segoe UI',Helvetica,Arial,sans-serif;"
    serif = "font-family:Georgia,'Times New Roman',serif;"
    bloques = []
    for nf, (fab, prods) in enumerate(agrupar(nuevas)):
        # fabricante
        bloques.append(f"""
        <tr><td colspan="2" style="{serif}font-size:26px;line-height:32px;color:#111827;padding:{'8' if nf == 0 else '32'}px 0 4px 0;">{e(fab)}</td></tr>""")
        for prod, rs in prods:
            # producto, con una línea debajo como en la web
            bloques.append(f"""
        <tr><td colspan="2" style="{fuente}font-size:15px;line-height:20px;font-weight:bold;color:#111827;padding:14px 0 8px 0;border-bottom:1px solid #111827;">{e(prod)}
          <span style="font-weight:normal;font-size:11px;letter-spacing:1px;color:#6b7280;">&nbsp;&nbsp;{len(rs)} CVE{'S' if len(rs) != 1 else ''}</span></td></tr>""")
            for i, r in enumerate(rs):
                sev = r["severidad"] if r["severidad"] in SEV_ES else "NONE"
                color = SEV_COLOR.get(sev, "#6b7280")
                score = f"{r['cvss']:.1f}" if r["cvss"] is not None else "&mdash;"
                borde = "border-top:1px solid #e5e7eb;" if i else ""
                kev = ('&nbsp;&nbsp;<span style="color:#dc2626;font-size:11px;font-weight:bold;letter-spacing:1px;">'
                       '&#9679;&nbsp;EXPLOTADA</span>' if r["explotada_kev"] else "")
                fixes = versiones_arreglo(r)
                fix = (f'<tr><td style="{fuente}font-size:13px;line-height:19px;color:#374151;padding-top:8px;">Actualizar a: '
                       f'<b style="color:#047857;">{e(", ".join(fixes))}</b></td></tr>') if fixes else ""
                bloques.append(f"""
        <tr>
          <td width="70" valign="top" style="{fuente}{borde}padding:16px 0;width:70px;">
            <div style="font-size:22px;font-weight:bold;color:{color};line-height:24px;">{score}</div>
            <div style="font-size:10px;font-weight:bold;letter-spacing:1px;text-transform:uppercase;color:{color};line-height:16px;">{e(SEV_ES.get(sev, 'Sin puntuar'))}</div>
          </td>
          <td valign="top" style="{fuente}{borde}padding:16px 0;">
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
              <tr><td style="{fuente}font-size:15px;line-height:22px;"><a href="{e(r['url'])}" style="color:#111827;font-weight:bold;text-decoration:none;"><span style="color:#111827;">{e(r['cve'])}</span></a>{kev}</td></tr>
              <tr><td style="{fuente}font-size:14px;line-height:21px;color:#374151;padding-top:4px;">{e(vp_extracto(r['descripcion']))}</td></tr>
              {fix}
            </table>
          </td>
        </tr>""")
    boton = f"""
        <tr><td colspan="2" style="padding-top:28px;">
          <table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>
            <td bgcolor="#111827" style="background-color:#111827;border-radius:20px;padding:11px 20px;{fuente}">
              <a href="{e(url)}" style="color:#ffffff;font-size:14px;text-decoration:none;font-weight:bold;"><span style="color:#ffffff;">Ver el informe completo</span></a>
            </td></tr></table>
        </td></tr>""" if url else ""
    n = len(nuevas)
    titulo = f"{n} vulnerabilidad{'es' if n != 1 else ''} nueva{'s' if n != 1 else ''}"
    return f"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background-color:#f3f4f6;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="#f3f4f6" style="background-color:#f3f4f6;">
  <tr><td align="center" style="padding:24px 12px;">
    <table role="presentation" width="640" cellpadding="0" cellspacing="0" border="0" bgcolor="#ffffff"
           style="width:640px;max-width:640px;background-color:#ffffff;border:1px solid #e5e7eb;">
      <tr><td style="padding:28px 32px 4px 32px;{fuente}">
        <div style="font-size:11px;letter-spacing:2px;text-transform:uppercase;color:#6b7280;">Seguridad perimetral</div>
        <div style="{serif}font-size:32px;line-height:40px;color:#111827;padding-top:6px;padding-bottom:14px;border-bottom:1px solid #111827;">{titulo}</div>
      </td></tr>
      <tr><td style="padding:8px 32px 32px 32px;">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">{''.join(bloques)}{html_clientes(nuevas, afect, fuente, serif)}{boton}
        </table>
      </td></tr>
    </table>
    <table role="presentation" width="640" cellpadding="0" cellspacing="0" border="0" style="width:640px;max-width:640px;">
      <tr><td align="center" style="padding-top:12px;{fuente}font-size:12px;color:#9ca3af;">Fuentes: NVD, CVE.org y CISA KEV</td></tr>
    </table>
  </td></tr>
</table>
</body></html>"""


# ----------------------------------------------------------------------------- clientes afectados

ESTADOS = {
    "explotable": ("Vulnerable y explotable", "#dc2626", "#fef2f2"),
    "revisar": ("Vulnerable por versión · revisar si es explotable", "#c2410c", "#fff7ed"),
    "version": ("Revisar versión", "#6b7280", "#f3f4f6"),
}


def cargar_clientes():
    """Inventario (con alias) y nombres reales, desde los secretos de GitHub o desde archivos locales de prueba.
    En GitHub Actions cada nombre se marca para que nunca aparezca en los registros públicos."""
    inv = afectacion.desempaquetar(os.environ.get("INVENTARIO_CLIENTES", ""))
    nombres = afectacion.desempaquetar(os.environ.get("CLIENTES_NOMBRES", ""))
    if not inv:
        return None
    nombres = nombres or {}
    if os.environ.get("GITHUB_ACTIONS"):
        for n in nombres.values():
            print(f"::add-mask::{n}")
    print(f"Inventario cargado: {len(inv)} equipos de {len(nombres)} clientes.", file=sys.stderr)
    return {"inventario": inv, "nombres": nombres}


def calcular_afectados(nuevas, clientes):
    if not clientes:
        return None
    por_cve = {r["cve"]: afectacion.afectados(r, clientes["inventario"]) for r in nuevas}
    total = sum(len(v) for v in por_cve.values())
    print(f"Equipos de clientes afectados: {total}", file=sys.stderr)   # solo el número, nunca nombres
    return {"por_cve": {k: v for k, v in por_cve.items() if v}, "nombres": clientes["nombres"]}


def texto_clientes(nuevas, afect):
    if afect is None:
        return []
    lineas = ["", "CLIENTES AFECTADOS", "==================", ""]
    if not afect["por_cve"]:
        return lineas + ["Ningún cliente del inventario está afectado por estas CVEs.", ""]
    for r in nuevas:
        for eq in afect["por_cve"].get(r["cve"], []):
            nombre = afect["nombres"].get(eq["alias"], eq["alias"])
            lineas.append(f"* {nombre} · {eq['producto']} {eq['version']} · {r['cve']} · {ESTADOS[eq['estado']][0]}"
                          + (f" · actualizar a {eq['arreglo']}" if eq.get("arreglo") and eq["arreglo"] != "Consultar aviso" else ""))
            if eq["estado"] == "revisar":
                lineas.append(f"  Condición: {' / '.join(eq['condiciones'])}")
    return lineas + [""]


def html_clientes(nuevas, afect, fuente, serif):
    if afect is None:
        return ""
    e = html.escape
    filas = [f"""
        <tr><td colspan="2" style="{serif}font-size:26px;line-height:32px;color:#111827;padding:36px 0 4px 0;">Clientes afectados</td></tr>"""]
    if not afect["por_cve"]:
        filas.append(f"""
        <tr><td colspan="2" style="{fuente}font-size:14px;color:#374151;padding:8px 0;">Ningún cliente del inventario está afectado por estas CVEs.</td></tr>""")
        return "".join(filas)
    for r in nuevas:
        equipos = afect["por_cve"].get(r["cve"])
        if not equipos:
            continue
        filas.append(f"""
        <tr><td colspan="2" style="{fuente}font-size:15px;line-height:20px;font-weight:bold;color:#111827;padding:14px 0 8px 0;border-bottom:1px solid #111827;">{e(r['cve'])}
          <span style="font-weight:normal;font-size:13px;color:#6b7280;">&nbsp;&nbsp;{e(r['fabricante'])} · {e(r['producto'])}</span></td></tr>""")
        for i, eq in enumerate(equipos):
            etiqueta, color, fondo = ESTADOS[eq["estado"]]
            nombre = afect["nombres"].get(eq["alias"], eq["alias"])
            borde = "border-top:1px solid #e5e7eb;" if i else ""
            arreglo = eq.get("arreglo")
            arreglo_html = (f'<tr><td style="{fuente}font-size:13px;color:#374151;padding-top:4px;">Actualizar a: '
                            f'<b style="color:#047857;">{e(arreglo)}</b></td></tr>') if arreglo and arreglo != "Consultar aviso" else ""
            cond_html = ""
            if eq["estado"] == "revisar" and eq["condiciones"]:
                cond_html = (f'<tr><td style="{fuente}font-size:13px;line-height:19px;color:#374151;padding:6px 0 0 10px;'
                             f'border-left:3px solid #c2410c;">Solo explotable si: {e(" / ".join(eq["condiciones"]))}</td></tr>')
            elif eq["estado"] == "version":
                cond_html = (f'<tr><td style="{fuente}font-size:13px;color:#6b7280;padding-top:4px;">No se puede determinar '
                             f'si esta versión está afectada: confírmalo en el aviso del fabricante.</td></tr>')
            filas.append(f"""
        <tr><td colspan="2" style="{fuente}{borde}padding:12px 0;">
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
            <tr><td style="{fuente}font-size:15px;line-height:22px;"><b style="color:#111827;">{e(nombre)}</b>
              <span style="color:#374151;">&nbsp;·&nbsp;{e(eq['producto'])} {e(eq['version'])}</span></td></tr>
            <tr><td style="{fuente}padding-top:4px;"><span style="background-color:{fondo};color:{color};font-size:11px;font-weight:bold;letter-spacing:1px;">&nbsp;{e(etiqueta.upper())}&nbsp;</span></td></tr>
            {arreglo_html}{cond_html}
          </table>
        </td></tr>""")
    return "".join(filas)


def enviar(nuevas, url, afect=None):
    usuario = os.environ.get("SMTP_USER")
    clave = os.environ.get("SMTP_PASSWORD")
    if not usuario or not clave:
        sys.exit("Faltan SMTP_USER y/o SMTP_PASSWORD: no se puede enviar el correo.")
    para = os.environ.get("AVISO_PARA") or usuario
    msg = EmailMessage()
    msg["Subject"] = asunto(nuevas)
    msg["From"] = f"Vulns perimetrales <{usuario}>"
    msg["To"] = para
    msg.set_content(cuerpo_texto(nuevas, url, afect))
    msg.add_alternative(cuerpo_html(nuevas, url, afect), subtype="html")
    host = os.environ.get("SMTP_HOST", "smtp.gmail.com")
    puerto = int(os.environ.get("SMTP_PORT", "465"))
    with smtplib.SMTP_SSL(host, puerto, context=ssl.create_default_context(), timeout=60) as s:
        s.login(usuario, clave)
        s.send_message(msg)
    print(f"Correo enviado con {len(nuevas)} CVE(s).", file=sys.stderr)


# ----------------------------------------------------------------------------- main

def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    p = argparse.ArgumentParser(description="Avisos por correo de CVEs nuevas en productos perimetrales")
    p.add_argument("--probar", action="store_true", help="envía un correo de prueba con las 3 CVEs más recientes")
    p.add_argument("--vista-previa", metavar="HTML", help="no envía nada: guarda el correo de prueba en este archivo HTML")
    p.add_argument("--cves", metavar="LISTA", help="para la prueba: CVEs concretas del histórico publicado, separadas por comas")
    a = p.parse_args()

    hasta = datetime.now(timezone.utc)
    desde = hasta - timedelta(days=VENTANA_DIAS)
    api_key = os.environ.get("NVD_API_KEY")
    url = os.environ.get("INFORME_URL", "")

    kev = vp.descargar_kev()
    cves = vp.obtener_cves(desde, hasta, api_key, RUTA_CACHE_NVD, max_dias=VENTANA_DIAS)
    filtro = [x.strip().lower() for x in os.environ.get("AVISO_FABRICANTES", "").split(",") if x.strip()]
    seleccion = [k for k, f in vp.FABRICANTES.items() if not filtro or k in filtro or f["nombre"].lower() in filtro]
    if filtro and not seleccion:
        sys.exit(f"AVISO_FABRICANTES no coincide con ningún fabricante: {filtro}")
    actuales = vp.filtrar(cves, seleccion, kev, 0)
    por_id = {c["id"]: c for c in cves}

    estado = cargar_estado()
    ahora = hasta.strftime("%Y-%m-%dT%H:%M:%SZ")
    avisadas = (estado or {}).get("avisadas", {})

    clientes = cargar_clientes()

    if a.probar or a.vista_previa:
        if a.cves:
            prueba = cves_del_historico([c.strip().upper() for c in a.cves.split(",") if c.strip()], url)
        else:
            prueba = sorted(actuales, key=lambda r: r["publicado"], reverse=True)[:3]
            vp.enriquecer(prueba, por_id, RUTA_CACHE_CNA)
            vp.anadir_arreglos_fabricante(prueba, RUTA_CACHE_AVISOS)
        if not prueba:
            sys.exit("No hay CVEs con las que hacer la prueba.")
        afect = calcular_afectados(prueba, clientes)
        if a.vista_previa:
            with open(a.vista_previa, "w", encoding="utf-8") as f:
                f.write(cuerpo_html(prueba, url, afect))
            print(f"Asunto: {asunto(prueba)}", file=sys.stderr)
            print(f"Vista previa guardada en {a.vista_previa}", file=sys.stderr)
        else:
            enviar(prueba, url, afect)
        return

    if estado is None:
        # Primera ejecución: se marca todo lo actual como ya avisado, sin enviar nada
        guardar_estado({r["cve"]: ahora for r in actuales})
        print(f"Primera ejecución: {len(actuales)} CVEs actuales marcadas como avisadas. No se envía correo.",
              file=sys.stderr)
        return

    nuevas = [r for r in actuales if r["cve"] not in avisadas]
    if nuevas:
        vp.enriquecer(nuevas, por_id, RUTA_CACHE_CNA)
        vp.anadir_arreglos_fabricante(nuevas, RUTA_CACHE_AVISOS)   # versiones corregidas por rama (Cisco)
        nuevas.sort(key=lambda r: (not r["explotada_kev"], -(r["cvss"] or 0)))
        enviar(nuevas, url, calcular_afectados(nuevas, clientes))
        for r in nuevas:
            avisadas[r["cve"]] = ahora
    else:
        print("Sin CVEs nuevas.", file=sys.stderr)

    # se olvidan las avisadas hace más de RECUERDA_DIAS (ya no pueden volver a aparecer en la ventana)
    limite = (hasta - timedelta(days=RECUERDA_DIAS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    guardar_estado({k: v for k, v in avisadas.items() if v >= limite})


if __name__ == "__main__":
    main()
