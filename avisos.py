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

import vulns_perimetrales as vp

CARPETA = os.path.dirname(os.path.abspath(__file__))
RUTA_ESTADO = os.path.join(CARPETA, ".estado_avisos.json")
RUTA_CACHE_NVD = os.path.join(CARPETA, ".cache_nvd_avisos.json")
RUTA_CACHE_CNA = os.path.join(CARPETA, ".cache_cna.json")
VENTANA_DIAS = 3          # se revisa lo publicado en los últimos 3 días (NVD a veces indexa con retraso)
RECUERDA_DIAS = 30        # cuánto tiempo se recuerda que una CVE ya se avisó
SEV_ES = {"CRITICAL": "Crítica", "HIGH": "Alta", "MEDIUM": "Media", "LOW": "Baja"}
SEV_COLOR = {"CRITICAL": "#86198f", "HIGH": "#c2410c", "MEDIUM": "#a16207", "LOW": "#3f6212"}


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


def cuerpo_texto(nuevas, url):
    lineas = [f"Se han publicado {len(nuevas)} vulnerabilidades nuevas en productos perimetrales:", ""]
    for r in nuevas:
        score = f"{r['cvss']:.1f}" if r["cvss"] is not None else "sin puntuar"
        lineas.append(f"- {r['cve']} · {r['fabricante']} · {r['producto']} · CVSS {score}"
                      + ("  [EXPLOTADA - CISA KEV]" if r["explotada_kev"] else ""))
        lineas.append(f"  {vp_extracto(r['descripcion'])}")
        if versiones_arreglo(r):
            lineas.append("  Actualizar a: " + ", ".join(versiones_arreglo(r)))
        lineas.append(f"  {r['url']}")
        lineas.append("")
    if url:
        lineas.append(f"Informe completo: {url}")
    return "\n".join(lineas)


def versiones_arreglo(r):
    """Versiones a las que actualizar (sin las entradas genéricas tipo «Consultar aviso»)."""
    return sorted({v["corregida"] for v in r["versiones"] if v["corregida"] != "Consultar aviso"})


def vp_extracto(texto, maximo=220):
    t = " ".join(texto.split())
    primera = t.split(". ")[0]
    primera = primera if primera.endswith(".") else primera + "."
    return primera if len(primera) <= maximo else primera[: maximo - 1] + "…"


def cuerpo_html(nuevas, url):
    """HTML compatible con Outlook de escritorio (motor de Word): solo tablas de ancho fijo, estilos en
    línea en cada celda y botón hecho con una celda de color. Nada de max-width, margin ni padding en <div>/<span>."""
    e = html.escape
    fuente = "font-family:'Segoe UI',Helvetica,Arial,sans-serif;"
    filas = []
    for i, r in enumerate(nuevas):
        sev = r["severidad"] if r["severidad"] in SEV_ES else "NONE"
        color = SEV_COLOR.get(sev, "#6b7280")
        score = f"{r['cvss']:.1f}" if r["cvss"] is not None else "&mdash;"
        borde = "border-top:1px solid #e5e7eb;" if i else ""
        kev = ('&nbsp;&nbsp;<span style="color:#dc2626;font-size:11px;font-weight:bold;letter-spacing:1px;">'
               '&#9679;&nbsp;EXPLOTADA</span>' if r["explotada_kev"] else "")
        fixes = versiones_arreglo(r)
        fix = (f'<tr><td style="{fuente}font-size:13px;color:#374151;padding-top:8px;">Actualizar a: '
               f'<b style="color:#047857;">{e(", ".join(fixes))}</b></td></tr>') if fixes else ""
        filas.append(f"""
        <tr>
          <td width="70" valign="top" style="{fuente}{borde}padding:18px 0;width:70px;">
            <div style="font-size:22px;font-weight:bold;color:{color};line-height:24px;">{score}</div>
            <div style="font-size:10px;font-weight:bold;letter-spacing:1px;text-transform:uppercase;color:{color};line-height:16px;">{e(SEV_ES.get(sev, 'Sin puntuar'))}</div>
          </td>
          <td valign="top" style="{fuente}{borde}padding:18px 0;">
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
              <tr><td style="{fuente}font-size:15px;line-height:22px;"><a href="{e(r['url'])}" style="color:#111827;font-weight:bold;text-decoration:none;">{e(r['cve'])}</a>{kev}</td></tr>
              <tr><td style="{fuente}font-size:13px;line-height:20px;color:#6b7280;">{e(r['fabricante'])} &middot; {e(r['producto'])}</td></tr>
              <tr><td style="{fuente}font-size:14px;line-height:21px;color:#374151;padding-top:6px;">{e(vp_extracto(r['descripcion']))}</td></tr>
              {fix}
            </table>
          </td>
        </tr>""")
    boton = f"""
        <tr><td colspan="2" style="padding-top:24px;">
          <table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>
            <td bgcolor="#111827" style="background-color:#111827;border-radius:20px;padding:11px 20px;{fuente}">
              <a href="{e(url)}" style="color:#ffffff;font-size:14px;text-decoration:none;font-weight:bold;">Ver el informe completo</a>
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
      <tr><td style="padding:28px 32px 8px 32px;{fuente}">
        <div style="font-size:11px;letter-spacing:2px;text-transform:uppercase;color:#6b7280;">Seguridad perimetral</div>
        <div style="font-family:Georgia,'Times New Roman',serif;font-size:28px;line-height:36px;color:#111827;padding-top:6px;">{titulo}</div>
      </td></tr>
      <tr><td style="padding:8px 32px 32px 32px;">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">{''.join(filas)}{boton}
        </table>
      </td></tr>
    </table>
    <table role="presentation" width="640" cellpadding="0" cellspacing="0" border="0" style="width:640px;max-width:640px;">
      <tr><td align="center" style="padding-top:12px;{fuente}font-size:12px;color:#9ca3af;">Fuentes: NVD, CVE.org y CISA KEV</td></tr>
    </table>
  </td></tr>
</table>
</body></html>"""


def enviar(nuevas, url):
    usuario = os.environ.get("SMTP_USER")
    clave = os.environ.get("SMTP_PASSWORD")
    if not usuario or not clave:
        sys.exit("Faltan SMTP_USER y/o SMTP_PASSWORD: no se puede enviar el correo.")
    para = os.environ.get("AVISO_PARA") or usuario
    msg = EmailMessage()
    msg["Subject"] = asunto(nuevas)
    msg["From"] = f"Vulns perimetrales <{usuario}>"
    msg["To"] = para
    msg.set_content(cuerpo_texto(nuevas, url))
    msg.add_alternative(cuerpo_html(nuevas, url), subtype="html")
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
    a = p.parse_args()

    hasta = datetime.now(timezone.utc)
    desde = hasta - timedelta(days=VENTANA_DIAS)
    api_key = os.environ.get("NVD_API_KEY")
    url = os.environ.get("INFORME_URL", "")

    kev = vp.descargar_kev()
    cves = vp.obtener_cves(desde, hasta, api_key, RUTA_CACHE_NVD, max_dias=VENTANA_DIAS)
    actuales = vp.filtrar(cves, list(vp.FABRICANTES), kev, 0)
    por_id = {c["id"]: c for c in cves}

    estado = cargar_estado()
    ahora = hasta.strftime("%Y-%m-%dT%H:%M:%SZ")
    avisadas = (estado or {}).get("avisadas", {})

    if a.probar or a.vista_previa:
        prueba = sorted(actuales, key=lambda r: r["publicado"], reverse=True)[:3]
        if not prueba:
            sys.exit("No hay CVEs recientes con las que hacer la prueba.")
        vp.enriquecer(prueba, por_id, RUTA_CACHE_CNA)
        if a.vista_previa:
            with open(a.vista_previa, "w", encoding="utf-8") as f:
                f.write(cuerpo_html(prueba, url))
            print(f"Asunto: {asunto(prueba)}", file=sys.stderr)
            print(f"Vista previa guardada en {a.vista_previa}", file=sys.stderr)
        else:
            enviar(prueba, url)
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
        nuevas.sort(key=lambda r: (not r["explotada_kev"], -(r["cvss"] or 0)))
        enviar(nuevas, url)
        for r in nuevas:
            avisadas[r["cve"]] = ahora
    else:
        print("Sin CVEs nuevas.", file=sys.stderr)

    # se olvidan las avisadas hace más de RECUERDA_DIAS (ya no pueden volver a aparecer en la ventana)
    limite = (hasta - timedelta(days=RECUERDA_DIAS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    guardar_estado({k: v for k, v in avisadas.items() if v >= limite})


if __name__ == "__main__":
    main()
