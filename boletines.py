#!/usr/bin/env python3
"""
Radar de boletines: avisos de los fabricantes que NVD no ve.

NVD solo recoge CVEs, y las clasifica por el producto vulnerable. Se le escapan:
  - las «security hardening releases» y los preavisos, que salen sin CVE (o con la CVE semanas después);
  - el impacto de un componente de terceros (PHP, OpenSSL…), cuyas CVEs constan como del componente.

Este módulo lee los feeds RSS oficiales de boletines.json y se queda con esos boletines. Las reglas se aplican al
título y son las mismas que usa el radar de n8n (n8n/radar_leer.js): si cambias una, cambia la otra.

Uso:
  python boletines.py            # lista los boletines relevantes de los últimos 30 días
  python boletines.py --dias 7
"""
import argparse
import json
import os
import re
import sys
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime

CARPETA = os.path.dirname(os.path.abspath(__file__))
RUTA_CONFIG = os.path.join(CARPETA, "boletines.json")
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)


def cargar_config(ruta=RUTA_CONFIG):
    with open(ruta, encoding="utf-8") as f:
        return json.load(f)


def _fecha(texto):
    """RFC 822 (la mayoría de los RSS) o ISO 8601 (Palo Alto, Atom) → ISO en UTC."""
    texto = (texto or "").strip()
    if not texto:
        return None
    try:
        d = parsedate_to_datetime(texto)
    except (TypeError, ValueError):
        try:
            d = datetime.fromisoformat(texto.replace("Z", "+00:00"))
        except ValueError:
            return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _texto(nodo):
    return " ".join("".join(nodo.itertext()).split()) if nodo is not None else ""


def _hijo(item, nombre):
    """Primer hijo con ese nombre local, ignorando el espacio de nombres (feedburner:origLink, atom:link…)."""
    for h in item:
        if h.tag.rsplit("}", 1)[-1] == nombre:
            return h
    return None


def descargar(url, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (informe-vulns; radar de boletines)"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def leer_feed(contenido):
    """Entradas de un RSS 2.0 o Atom: [{id, titulo, url, fecha, resumen}]."""
    raiz = ET.fromstring(contenido)
    entradas = [n for n in raiz.iter() if n.tag.rsplit("}", 1)[-1] in ("item", "entry")]
    salida = []
    for it in entradas:
        titulo = _texto(_hijo(it, "title"))
        enlace = _hijo(it, "origLink")            # Fortinet: el <link> es una redirección de FeedBlitz
        url = _texto(enlace) if enlace is not None else ""
        if not url:
            enlace = _hijo(it, "link")
            url = (enlace.get("href") or _texto(enlace)) if enlace is not None else ""
        guid = _texto(_hijo(it, "guid")) or _texto(_hijo(it, "id")) or url
        fecha = None
        for campo in ("pubDate", "published", "updated", "date"):
            fecha = _fecha(_texto(_hijo(it, campo)))
            if fecha:
                break
        resumen = re.sub(r"<[^>]+>", " ", _texto(_hijo(it, "description")) or _texto(_hijo(it, "summary")))
        if "vs_f=" in url:                         # Cisco: el resto de la URL es solo seguimiento del RSS
            url = url.split("?")[0]
        salida.append({"id": guid.split("?")[0], "titulo": titulo, "url": url, "fecha": fecha,
                       "resumen": " ".join(resumen.split())})
    return salida


def clasificar(titulo, tipo, reglas):
    """«terceros», «sin-cve», «comunicado» o None (boletín normal con CVE propia: ya lo cubre NVD)."""
    t = titulo.lower()
    if re.search(reglas["terceros"], t):
        return "terceros"
    if re.search(reglas["sin_cve"], t):
        return "sin-cve"
    if tipo == "blog-psirt" or (tipo == "blog" and re.search(reglas["blog"], t)):
        return "comunicado"
    return None


def obtener(dias, nombres, config=None):
    """Boletines relevantes de los últimos `dias` días, del más reciente al más antiguo.
    `nombres`: clave del fabricante → nombre que se muestra (FABRICANTES de vulns_perimetrales).
    Un feed que falla no para nada: se avisa por stderr y se sigue con los demás."""
    config = config or cargar_config()
    corte = (datetime.now(timezone.utc) - timedelta(days=dias)).strftime("%Y-%m-%dT%H:%M:%SZ")
    vistos, salida = set(), []
    for feed in config["feeds"]:
        if feed["fabricante"] not in nombres:
            continue
        try:
            entradas = leer_feed(descargar(feed["url"]))
        except Exception as e:  # noqa: BLE001 - un feed caído no debe romper el informe ni los avisos
            print(f"Aviso: no se ha podido leer {feed['fuente']} ({e})", file=sys.stderr)
            continue
        for e in entradas:
            clase = clasificar(e["titulo"], feed["tipo"], config["reglas"])
            if not clase or not e["fecha"] or e["fecha"] < corte or e["id"] in vistos:
                continue
            if feed.get("productos") and not re.search(feed["productos"], e["titulo"].lower()):
                continue
            vistos.add(e["id"])
            salida.append({
                "id": e["id"], "fabricante": nombres[feed["fabricante"]], "fuente": feed["fuente"],
                "clase": clase, "etiqueta": config["etiquetas"][clase],
                "titulo": e["titulo"], "url": e["url"], "fecha": e["fecha"],
                "cves": sorted({c.upper() for c in CVE_RE.findall(e["titulo"] + " " + e["resumen"])}),
            })
    salida.sort(key=lambda b: b["fecha"], reverse=True)
    return salida


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    p = argparse.ArgumentParser(description="Boletines de los fabricantes que NVD no ve")
    p.add_argument("--dias", type=int, default=30)
    a = p.parse_args()
    import vulns_perimetrales as vp
    nombres = {k: f["nombre"] for k, f in vp.FABRICANTES.items()}
    for b in obtener(a.dias, nombres):
        print(f"{b['fecha'][:10]}  {b['fabricante']:<20} [{b['etiqueta']}] {b['titulo']}")
        print(f"            {b['url']}" + (f"  ({', '.join(b['cves'])})" if b["cves"] else ""))


if __name__ == "__main__":
    main()
