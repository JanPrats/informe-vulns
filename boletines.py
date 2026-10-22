#!/usr/bin/env python3
"""
Radar de boletines: avisos de los fabricantes que NVD no ve.

NVD solo recoge CVEs, y las clasifica por el producto vulnerable. Se le escapan:
  - las «security hardening releases» y los preavisos, que salen sin CVE (o con la CVE semanas después);
  - el impacto de un componente de terceros (PHP, OpenSSL…), cuyas CVEs constan como del componente.

Este módulo lee los feeds RSS oficiales de boletines.json y se queda con esos boletines. Las reglas se aplican al
título y son las mismas que usa el radar de n8n (n8n/radar_leer.js): si cambias una, cambia la otra.

Los avisos de terceros, además, son «vivos»: salen con los productos en investigación y el fabricante los va
revisando sin publicar un boletín nuevo. De esos se lee el detalle (página de Cisco y de FortiGuard, JSON de
Palo Alto) y se queda el estado de cada producto perimetral; avisos.py y el radar avisan cuando cambia.

Uso:
  python boletines.py            # lista los boletines relevantes de los últimos 30 días, con su detalle
  python boletines.py --dias 7
"""
import argparse
import html
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


# ----------------------------------------------------------------------------- detalle de los avisos vivos
# Misma lógica en n8n/radar_leer.js. Todo se lee como líneas de texto, porque las páginas cambian de maquetación
# más a menudo que de redacción.

ESTADOS = ("afectado", "investigando", "no afectado")       # si un producto sale en dos listas, manda el primero
MESES_EN = ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec")


def _lineas(pagina):
    """HTML → líneas de texto limpias: un bloque (párrafo, celda, elemento de lista…) por línea."""
    t = re.sub(r"<(script|style)\b[\s\S]*?</\1>", " ", pagina, flags=re.I)
    t = re.sub(r"</?(?:li|br|p|div|h\d|tr|td|th|dt|dd|ul|ol|table)\b[^>]*>", "\n", t, flags=re.I)
    t = html.unescape(re.sub(r"<[^>]+>", " ", t))
    return [x for x in (" ".join(l.split()) for l in t.split("\n")) if x]


def _poner(estado, producto, valor):
    if producto not in estado or ESTADOS.index(valor) < ESTADOS.index(estado[producto]):
        estado[producto] = valor


def _es_producto(linea, perimetrales):
    """Una línea que nombra un producto perimetral, no una frase ni un comando («asa# show …») que lo menciona."""
    return (len(linea) <= 100 and not linea.endswith((".", ":")) and "#" not in linea
            and re.search(perimetrales, linea.lower()))


def _iso(anio, mes, dia, hora="00:00"):
    return f"{int(anio):04d}-{MESES_EN.index(mes[:3].lower()) + 1:02d}-{int(dia):02d}T{hora}:00Z"


def _cisco(lineas, perimetrales):
    """Página del aviso: listas «Vulnerable Products», «Products Confirmed Not Vulnerable» y «Products Under
    Investigation», versión, «Last Updated» (o «First Published» si no hay revisiones) y la última línea del
    historial de revisiones."""
    secciones = {"products under investigation": "investigando", "vulnerable products": "afectado",
                 "products confirmed not vulnerable": "no afectado"}
    fin = re.compile(r"^(workarounds|fixed software|exploitation and public announcements|details|source)$")
    estado, actual = {}, None
    for l in lineas:
        k = l.lower()
        if k in secciones:
            actual = secciones[k]
        elif fin.match(k):
            actual = None
        elif actual and _es_producto(l, perimetrales):
            _poner(estado, l, actual)
    texto = " ".join(lineas)
    m = re.search(r"(?:Last Updated|First Published):\s*(\d{4}) ([A-Za-z]+) (\d{1,2}) (\d{1,2}:\d\d)", texto)
    v = re.search(r"\bVersion (\d+(?:\.\d+)+)", texto)
    nota = ""
    if "Revision History" in lineas:
        resto = lineas[lineas.index("Revision History"):]
        if "Date" in resto and len(resto) > resto.index("Date") + 2:
            nota = resto[resto.index("Date") + 2]            # filas: versión, descripción…; la primera es la última
    return {"version": v.group(1) if v else None, "nota": nota, "estado": estado,
            "actualizado": _iso(m.group(1), m.group(2), m.group(3), m.group(4).zfill(5)) if m else None}


def _fortinet(lineas, perimetrales):
    """Página FG-IR: listas «Products Under Investigation:», «Products confirmed NOT Impacted:» (y las de
    afectados), la tabla Version / Affected / Solution, «Updated Date» (o «Published Date») y la última línea
    de «Timeline»."""
    fin = re.compile(r"^(solutions?|timeline|references|virtual patch|workarounds?|acknowledge?ments?|ir number)$")
    # títulos de lista: «Products Under Investigation:», y en los avisos antiguos también «Affected Products»
    titulo = re.compile(r":$|^(the following )?products?\b|\bproducts?$")
    estado, actual, tabla, nota, actualizado = {}, None, False, "", None
    i = 0
    while i < len(lineas):
        l, k = lineas[i], lineas[i].lower()
        if k == "version" and lineas[i + 1:i + 3] == ["Affected", "Solution"]:
            actual, tabla, i = "afectado", True, i + 3
            continue
        if titulo.search(k) and len(k) < 80 and not re.search(perimetrales, k):
            tabla = False
            actual = ("investigando" if "investigation" in k else
                      "no afectado" if re.search(r"\bnot (impacted|affected|vulnerable)", k) else
                      "afectado" if re.search(r"\b(impacted|affected|vulnerable)\b", k) else None)
        elif fin.match(k):
            actual, tabla = None, False
            if k == "timeline":                               # «2026-10-22: Products under investigation…»
                fechas = [x for x in lineas[i + 1:i + 30] if re.match(r"\d{4}-\d\d-\d\d:", x)]
                nota = max(fechas)[11:].strip() if fechas else ""
        elif k in ("published date", "updated date") and i + 1 < len(lineas):   # «Updated Date» va después
            m = re.match(r"([A-Za-z]{3})\w* (\d{1,2}), (\d{4})", lineas[i + 1])
            actualizado = _iso(m.group(3), m.group(1), m.group(2)) if m else actualizado
        elif actual and _es_producto(l, perimetrales):
            if tabla:                                         # fila: producto, versiones afectadas, solución
                siguiente = lineas[i + 1].lower() if i + 1 < len(lineas) else ""
                _poner(estado, l, "no afectado" if siguiente.startswith("not affected") else "afectado")
                i += 3
                continue
            _poner(estado, l, actual)
        i += 1
    return {"version": None, "nota": nota, "estado": estado, "actualizado": actualizado}


def _paloalto(datos, perimetrales):
    """JSON del aviso (formato CVE 5): estado por producto en «affected» y revisiones en «timeline»."""
    cna = datos.get("containers", {}).get("cna", {})
    estado = {}
    for a in cna.get("affected", []):
        producto = " ".join((a.get("product") or "").split())
        if not re.search(perimetrales, producto.lower()):
            continue
        st = [v.get("status") for v in a.get("versions", [])]
        _poner(estado, producto, "afectado" if "affected" in st else
               "investigando" if "unknown" in st + [a.get("defaultStatus")] else "no afectado")
    tl = sorted(cna.get("timeline", []), key=lambda t: t.get("time", ""))
    return {"version": None, "nota": tl[-1].get("value", "") if tl else "", "estado": estado,
            "actualizado": _fecha(tl[-1].get("time")) if tl else None}


def detalle(url, tipo, perimetrales):
    """Estado de los productos perimetrales en un aviso vivo, o None si no se ha podido leer."""
    try:
        if tipo == "paloalto":
            return _paloalto(json.loads(descargar(re.sub(r"(paloaltonetworks\.com)/", r"\1/json/", url))),
                             perimetrales)
        crudo = descargar(url)
        try:
            pagina = crudo.decode("utf-8")
        except UnicodeDecodeError:                            # algunas páginas de Cisco vienen en Windows-1252
            pagina = crudo.decode("cp1252", "replace")
        lineas = _lineas(pagina)
        return (_cisco if tipo == "cisco" else _fortinet)(lineas, perimetrales)
    except Exception as e:  # noqa: BLE001 - un aviso que no se puede leer se vuelve a intentar en la siguiente
        print(f"Aviso: no se ha podido leer el detalle de {url} ({e})", file=sys.stderr)
        return None


def cambios(antes, ahora):
    """[(producto, estado anterior, estado nuevo)] entre dos lecturas de un aviso. None = no aparece.
    Si la nueva lectura sale vacía y la anterior no, se supone que la página ha cambiado de formato: sin cambios."""
    if not ahora:
        return []
    orden = lambda c: (ESTADOS.index(c[2]) if c[2] in ESTADOS else len(ESTADOS), c[0])   # afectados primero
    return sorted(((p, antes.get(p), ahora.get(p)) for p in set(antes) | set(ahora) if antes.get(p) != ahora.get(p)),
                  key=orden)


# ----------------------------------------------------------------------------- lectura de los feeds

def obtener(dias, nombres, config=None, con_detalle=False):
    """Boletines relevantes de los últimos `dias` días, del más reciente al más antiguo.
    `nombres`: clave del fabricante → nombre que se muestra (FABRICANTES de vulns_perimetrales).
    `con_detalle`: los de terceros de los feeds con «detalle» llevan además b["detalle"] (versión, fecha de la
    última revisión, nota y estado de cada producto perimetral), o None si no se ha podido leer.
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
            if con_detalle and clase == "terceros" and feed.get("detalle"):
                salida[-1]["detalle"] = detalle(e["url"], feed["detalle"],
                                                config["seguimiento"]["perimetrales"][feed["detalle"]])
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
    for b in obtener(a.dias, nombres, con_detalle=True):
        print(f"{b['fecha'][:10]}  {b['fabricante']:<20} [{b['etiqueta']}] {b['titulo']}")
        print(f"            {b['url']}" + (f"  ({', '.join(b['cves'])})" if b["cves"] else ""))
        if "detalle" in b:
            d = b["detalle"]
            if not d:
                print("            detalle: no se ha podido leer")
                continue
            print(f"            actualizado {d['actualizado']}" + (f" (v{d['version']})" if d["version"] else "")
                  + (f": {d['nota']}" if d["nota"] else ""))
            for est in ESTADOS:
                prods = [p for p, e in d["estado"].items() if e == est]
                if prods:
                    print(f"            {est}: {', '.join(prods)}")


if __name__ == "__main__":
    main()
