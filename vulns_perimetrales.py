#!/usr/bin/env python3
"""
Listado de vulnerabilidades recientes en productos de seguridad perimetral.

Fuentes:
  - NVD (NIST) API 2.0  -> CVEs publicados en los últimos N días
  - CISA KEV            -> marca las que se están explotando activamente

Uso:
  python vulns_perimetrales.py                 # últimos 7 días
  python vulns_perimetrales.py --dias 30 --min-cvss 7
  python vulns_perimetrales.py --fabricantes fortinet,paloalto --html informe.html --csv informe.csv

Opcional: define la variable de entorno NVD_API_KEY (gratis en
https://nvd.nist.gov/developers/request-an-api-key) para ir ~10x más rápido.

Solo usa la librería estándar de Python (3.8+).
"""
import argparse
import csv
import gzip
import json
import os
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
# Copia oficial de CISA en GitHub: la usa el HTML porque permite consultas desde el navegador (CORS)
KEV_URL_GITHUB = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"

# Fabricante -> patrones de búsqueda.
#   cpe:    nombre de vendor en CPE (cpe:2.3:*:<vendor>:...)
#   texto:  palabras clave en la descripción (minúsculas)
FABRICANTES = {
    "paloalto":    {"nombre": "Palo Alto Networks", "cpe": ["paloaltonetworks"],
                    "texto": ["pan-os", "globalprotect", "palo alto networks", "prisma access"]},
    "fortinet":    {"nombre": "Fortinet", "cpe": ["fortinet"],
                    "texto": ["fortios", "fortigate", "fortiproxy", "fortiweb", "fortimanager", "fortianalyzer",
                              "fortisiem", "fortiswitch", "fortiadc", "fortinet"]},
    "cisco":       {"nombre": "Cisco", "cpe": [],
                    "texto": ["adaptive security appliance", "cisco asa", "firepower", "secure firewall",
                              "cisco ise", "identity services engine", "anyconnect"]},
    "checkpoint":  {"nombre": "Check Point", "cpe": ["checkpoint"],
                    "texto": ["check point", "gaia os", "quantum security gateway"]},
    "sonicwall":   {"nombre": "SonicWall", "cpe": ["sonicwall"],
                    "texto": ["sonicwall", "sonicos", "sma 100", "sma1000"]},
    "juniper":     {"nombre": "Juniper Networks", "cpe": ["juniper"],
                    "texto": ["junos", "juniper networks", "srx series"]},
    "f5":          {"nombre": "F5", "cpe": ["f5"],
                    "texto": ["big-ip", "f5 networks", "nginx plus"]},
    "citrix":      {"nombre": "Citrix", "cpe": ["citrix"],
                    "texto": ["netscaler", "citrix adc", "citrix gateway"]},
    "ivanti":      {"nombre": "Ivanti", "cpe": ["ivanti", "pulsesecure"],
                    "texto": ["connect secure", "policy secure", "pulse secure", "ivanti neurons for zta"]},
    "sophos":      {"nombre": "Sophos", "cpe": ["sophos"],
                    "texto": ["sophos firewall", "sophos xg", "sophos utm"]},
    "watchguard":  {"nombre": "WatchGuard", "cpe": ["watchguard"],
                    "texto": ["watchguard", "fireware"]},
    "barracuda":   {"nombre": "Barracuda", "cpe": ["barracuda"],
                    "texto": ["barracuda"]},
    "zyxel":       {"nombre": "Zyxel", "cpe": ["zyxel"],
                    "texto": ["zyxel", "usg flex"]},
    "forcepoint":  {"nombre": "Forcepoint", "cpe": ["forcepoint"],
                    "texto": ["forcepoint"]},
    "stormshield": {"nombre": "Stormshield", "cpe": ["stormshield"],
                    "texto": ["stormshield"]},
    "array":       {"nombre": "Array Networks", "cpe": ["arraynetworks"],
                    "texto": ["array networks"]},
    "hillstone":   {"nombre": "Hillstone Networks", "cpe": ["hillstonenet"],
                    "texto": ["hillstone"]},
    "sangfor":     {"nombre": "Sangfor", "cpe": ["sangfor"],
                    "texto": ["sangfor"]},
    "netgate":     {"nombre": "Netgate", "cpe": ["netgate", "pfsense"],
                    "texto": ["pfsense", "netgate"]},
    "opnsense":    {"nombre": "OPNsense", "cpe": ["opnsense"],
                    "texto": ["opnsense"]},
}

# Nombres antiguos (con productos o varias marcas juntas) -> solo la marca. Sirve para actualizar lo ya guardado.
NOMBRES_ANTIGUOS = {
    "Cisco (ASA/FTD/FMC/ISE)": ["cisco"],
    "Citrix / NetScaler": ["citrix"],
    "Ivanti (Connect/Policy Secure)": ["ivanti"],
    "Array / Hillstone / Sangfor": ["array", "hillstone", "sangfor"],
    "pfSense / OPNsense": ["netgate", "opnsense"],
}


def marca_actual(r):
    """Nombre de fabricante vigente para un registro guardado con un nombre antiguo."""
    claves = NOMBRES_ANTIGUOS.get(r.get("fabricante"))
    if not claves:
        return r.get("fabricante")
    texto = " ".join([r.get("descripcion", ""), r.get("producto", ""), r.get("aviso", "")]).lower()
    for k in claves:
        if any(t in texto for t in FABRICANTES[k]["texto"] + FABRICANTES[k]["cpe"]):
            return FABRICANTES[k]["nombre"]
    return FABRICANTES[claves[0]]["nombre"]


# ----------------------------------------------------------------------------- red

LIMITE_PETICION = 120  # segundos máximos por petición; NVD a veces se queda "colgado" enviando datos


def http_json(url, headers=None, intentos=4, etiqueta=""):
    for i in range(intentos):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "vulns-perimetrales/1.0",
                                                      "Accept-Encoding": "gzip", **(headers or {})})
            inicio = time.time()
            with urllib.request.urlopen(req, timeout=30) as r:
                partes, leido = [], 0
                while True:
                    trozo = r.read(256 * 1024)
                    if not trozo:
                        break
                    partes.append(trozo)
                    leido += len(trozo)
                    if etiqueta:
                        print(f"\r  {etiqueta}: {leido / 1e6:.1f} MB ({time.time() - inicio:.0f}s)   ",
                              end="", file=sys.stderr, flush=True)
                    if time.time() - inicio > LIMITE_PETICION:
                        raise TimeoutError(f"la descarga supera {LIMITE_PETICION}s")
                if etiqueta:
                    print("\r" + " " * 60 + "\r", end="", file=sys.stderr)
                cuerpo = b"".join(partes)
                if r.headers.get("Content-Encoding") == "gzip":
                    cuerpo = gzip.decompress(cuerpo)
                return json.loads(cuerpo.decode("utf-8"))
        except Exception as e:  # 403/503 de NVD por rate-limit y cortes son habituales
            if i == intentos - 1:
                raise
            espera = 10 * (i + 1)
            print(f"\n  ! {e} -> reintento {i + 2}/{intentos} en {espera}s", file=sys.stderr)
            time.sleep(espera)


def descargar_nvd(desde, hasta, api_key=None):
    """Descarga todos los CVEs publicados entre desde y hasta (máx. 120 días por consulta)."""
    headers = {"apiKey": api_key} if api_key else {}
    pausa = 0.7 if api_key else 6.5  # límites públicos: 50 req/30s con key, 5 req/30s sin key
    fmt = "%Y-%m-%dT%H:%M:%S.000Z"
    cves, start, total = [], 0, None
    while True:
        params = {"pubStartDate": desde.strftime(fmt), "pubEndDate": hasta.strftime(fmt),
                  "resultsPerPage": 2000, "startIndex": start}
        pagina = f"NVD página {start // 2000 + 1}" + (f"/{-(-total // 2000)}" if total else "")
        data = http_json(f"{NVD_URL}?{urllib.parse.urlencode(params)}", headers, etiqueta=pagina)
        lote = data.get("vulnerabilities", [])
        cves.extend(reducir(v["cve"]) for v in lote)
        total = data.get("totalResults", 0)
        print(f"  NVD: {len(cves)}/{total} CVEs descargados", file=sys.stderr)
        start += len(lote)
        if not lote or start >= total:
            return cves
        time.sleep(pausa)


def reducir(cve):
    """Se queda solo con los campos que usamos (la caché ocupa ~10 veces menos)."""
    return {
        "id": cve["id"], "published": cve.get("published", ""), "vulnStatus": cve.get("vulnStatus", ""),
        "descriptions": [d for d in cve.get("descriptions", []) if d.get("lang") == "en"],
        "metrics": cve.get("metrics", {}), "weaknesses": cve.get("weaknesses", []),
        "configurations": [{"nodes": [{"cpeMatch": [{k: m[k] for k in CAMPOS_CPE if k in m} for m in n.get("cpeMatch", [])]}
                                      for n in c.get("nodes", [])]} for c in cve.get("configurations", [])],
        "references": [{"url": r.get("url", "")} for r in cve.get("references", [])][:6],
    }


CAMPOS_CPE = ("criteria", "vulnerable", "versionStartIncluding", "versionStartExcluding",
              "versionEndIncluding", "versionEndExcluding")
VERSION_CACHE = 2  # súbelo si cambia lo que guarda reducir()


def obtener_cves(desde, hasta, api_key, ruta_cache, max_dias=120):
    """Usa una caché local: en ejecuciones posteriores solo descarga lo publicado desde la última vez."""
    cache = None
    if ruta_cache and os.path.exists(ruta_cache):
        try:
            with open(ruta_cache, encoding="utf-8") as f:
                cache = json.load(f)
        except (OSError, ValueError):
            cache = None
    fmt = "%Y-%m-%dT%H:%M:%S%z"
    if cache and cache.get("v") != VERSION_CACHE:
        cache = None
    if cache:
        cves = {c["id"]: c for c in cache["cves"]}
        desde_cache = datetime.strptime(cache["desde"], fmt)
        # Si se pide más atrás de lo que cubre la caché, solo se descarga el tramo que falta
        if desde < desde_cache:
            print(f"Caché desde {desde_cache:%Y-%m-%d}; descargando el tramo anterior desde {desde:%Y-%m-%d}…", file=sys.stderr)
            for c in descargar_nvd(desde, desde_cache, api_key):
                cves.setdefault(c["id"], c)
            desde_cache = desde
            time.sleep(0.7 if api_key else 6.5)
        # 6 h de solape para recoger CVEs que NVD indexa con retraso
        inicio = datetime.strptime(cache["hasta"], fmt) - timedelta(hours=6)
        print(f"Caché encontrada; descargando solo lo publicado desde {inicio:%Y-%m-%d %H:%M} UTC…", file=sys.stderr)
        for c in descargar_nvd(max(inicio, desde), hasta, api_key):
            cves[c["id"]] = c
    else:
        cves = {c["id"]: c for c in descargar_nvd(desde, hasta, api_key)}
        desde_cache = desde
    # Mantenemos como mucho `max_dias` días en caché
    limite = max(desde_cache, hasta - timedelta(days=max_dias))
    cves = {k: c for k, c in cves.items() if c["published"] >= limite.strftime("%Y-%m-%dT%H:%M:%S")}
    if ruta_cache:
        with open(ruta_cache, "w", encoding="utf-8") as f:
            json.dump({"v": VERSION_CACHE, "desde": limite.strftime(fmt), "hasta": hasta.strftime(fmt), "cves": list(cves.values())}, f)
    corte = desde.strftime("%Y-%m-%dT%H:%M:%S")
    return [c for c in cves.values() if c["published"] >= corte]


EPSS_URL = "https://api.first.org/data/v1/epss"


def anadir_epss(registros):
    """Probabilidad de explotación en los próximos 30 días (EPSS, FIRST.org). 100 CVEs por consulta."""
    ids = sorted({r["cve"] for r in registros})
    datos = {}
    for i in range(0, len(ids), 100):
        lote = ids[i:i + 100]
        try:
            d = http_json(f"{EPSS_URL}?cve={','.join(lote)}&limit=100", intentos=2)
            for x in d.get("data", []):
                datos[x["cve"]] = (float(x["epss"]), float(x["percentile"]))
        except Exception as e:
            print(f"  ! EPSS: {e}", file=sys.stderr)
            return
    for r in registros:
        if r["cve"] in datos:
            r["epss"], r["epss_pct"] = datos[r["cve"]]


def descargar_kev():
    try:
        data = http_json(KEV_URL)
        return {v["cveID"]: v for v in data.get("vulnerabilities", [])}
    except Exception as e:
        print(f"  ! No se pudo descargar CISA KEV: {e}", file=sys.stderr)
        return {}


# ----------------------------------------------------------------------------- análisis

def cvss(cve):
    """Devuelve (score, severidad, versión) usando la mejor métrica disponible."""
    m = cve.get("metrics", {})
    for clave in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if m.get(clave):
            # preferimos la puntuación del propio fabricante (Secondary) si NVD aún no ha puntuado
            lista = sorted(m[clave], key=lambda x: x.get("type") != "Primary")
            d = lista[0]["cvssData"]
            sev = d.get("baseSeverity") or lista[0].get("baseSeverity", "")
            return d.get("baseScore", 0.0), sev.upper(), clave.replace("cvssMetric", "")
    return None, "SIN PUNTUAR", ""


def cpes(cve):
    out = []
    for conf in cve.get("configurations", []):
        for nodo in conf.get("nodes", []):
            for m in nodo.get("cpeMatch", []):
                out.append(m.get("criteria", "").lower())
    return out


def descripcion(cve):
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value", "")
    return ""


def fabricante_de(cve, seleccion):
    texto = descripcion(cve).lower()
    vendors_cpe = {c.split(":")[3] for c in cpes(cve) if c.count(":") > 4}
    for clave in seleccion:
        f = FABRICANTES[clave]
        # No usamos el CNA emisor: algunos PSIRT (p.ej. Palo Alto) publican CVEs de productos de terceros.
        if any(v in vendors_cpe for v in f["cpe"]) or any(t in texto for t in f["texto"]):
            return f["nombre"]
    return None


def filtrar(cves, seleccion, kev, min_cvss):
    res = []
    for c in cves:
        if c.get("vulnStatus") == "Rejected":
            continue
        fab = fabricante_de(c, seleccion)
        if not fab:
            continue
        score, sev, ver = cvss(c)
        if min_cvss and (score is None or score < min_cvss):
            continue
        k = kev.get(c["id"])
        res.append({
            "cve": c["id"],
            "fabricante": fab,
            "publicado": c.get("published", "")[:10],
            "cvss": score,
            "severidad": sev,
            "version_cvss": ver,
            "explotada_kev": "SÍ" if k else "",
            "kev_fecha_limite": k.get("dueDate", "") if k else "",
            "cwe": ", ".join(sorted({d["value"] for w in c.get("weaknesses", []) for d in w.get("description", [])
                                     if d["value"].startswith("CWE-")})),
            "descripcion": descripcion(c),
            "vector": vector_cvss(c),
            "url": f"https://nvd.nist.gov/vuln/detail/{c['id']}",
        })
    # primero las explotadas, luego por CVSS descendente
    res.sort(key=lambda r: (r["explotada_kev"] != "SÍ", -(r["cvss"] or 0), r["publicado"]))
    return res


def kev_recientes(kev, desde, seleccion):
    """CVEs añadidos a KEV en el periodo (pueden ser CVEs antiguos que ahora se explotan)."""
    out = []
    for v in kev.values():
        try:
            fecha = datetime.strptime(v["dateAdded"], "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except (KeyError, ValueError):
            continue
        if fecha < desde:
            continue
        txt = f"{v.get('vendorProject','')} {v.get('product','')}".lower().replace(" ", "")
        for clave in seleccion:
            f = FABRICANTES[clave]
            pats = f["cpe"] + [t.replace(" ", "") for t in f["texto"]]
            if any(p in txt for p in pats):
                out.append(v)
                break
    return sorted(out, key=lambda v: v["dateAdded"], reverse=True)


# ----------------------------------------------------------------------------- explotación y versiones

CVE_ORG_URL = "https://cveawg.mitre.org/api/cve/"

# Métricas CVSS traducidas a lenguaje claro (v2, v3.x y v4.0)
TRADUCCION = {
    "AV": ("Vector de ataque", {"N": "Red (remoto)", "A": "Red adyacente (mismo segmento)", "L": "Acceso local",
                                "P": "Acceso físico"}),
    "AC": ("Complejidad", {"L": "Baja", "M": "Media", "H": "Alta"}),
    "AT": ("Condiciones previas", {"N": "Ninguna", "P": "Requiere una configuración o despliegue concreto"}),
    "PR": ("Privilegios", {"N": "Ninguno (sin autenticación)", "L": "Usuario con pocos privilegios",
                           "H": "Administrador"}),
    "Au": ("Autenticación", {"N": "Ninguna", "S": "Una vez", "M": "Varias veces"}),
    "UI": ("Interacción de usuario", {"N": "No necesaria", "R": "Necesaria", "P": "Necesaria (pasiva)",
                                      "A": "Necesaria (activa)"}),
}


def vector_cvss(cve):
    m = cve.get("metrics", {})
    for clave in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if m.get(clave):
            lista = sorted(m[clave], key=lambda x: x.get("type") != "Primary")
            return lista[0]["cvssData"].get("vectorString", "")
    return ""


def requisitos(vector):
    """Traduce el vector CVSS a [(etiqueta, valor), ...] y una frase resumen."""
    partes = dict(p.split(":", 1) for p in vector.split("/") if ":" in p and not p.startswith("CVSS"))
    filas = [(TRADUCCION[k][0], TRADUCCION[k][1].get(partes[k], partes[k])) for k in TRADUCCION if k in partes]
    if not partes:
        return [], ""
    donde = {"N": "remotamente", "A": "desde la red adyacente", "L": "con acceso local",
             "P": "con acceso físico"}.get(partes.get("AV"), "")
    auth = partes.get("PR", {"N": "N", "S": "L", "M": "L"}.get(partes.get("Au"), ""))
    quien = {"N": "sin autenticación", "L": "con una cuenta de usuario", "H": "con credenciales de administrador"}.get(auth, "")
    if partes.get("UI", "N") == "N":
        ui = "ni interacción del usuario" if quien.startswith("sin") else "sin interacción del usuario"
    else:
        ui = "y requiere que un usuario realice alguna acción"
    resumen = " ".join(x for x in ["Explotable", donde, quien, ui] if x)
    if partes.get("AT") == "P" or partes.get("AC") == "H":
        resumen += ", siempre que se den ciertas condiciones"
    return filas, resumen + "."


def _lineas_versiones(affected):
    """Convierte el bloque 'affected' del CNA (formato CVE 5) en filas de tabla."""
    filas, vistos = [], set()
    for a in affected or []:
        producto = a.get("product", "")
        if a.get("platforms") and a["platforms"] != ["Default"]:
            producto += f" ({', '.join(a['platforms'])})"
        for v in a.get("versions", []):
            if v.get("status") != "affected":
                continue
            ini = v.get("version", "")
            ini = "" if ini in ("0", "*", "n/a", "unspecified", "") else ini
            arreglos = [c["at"] for c in v.get("changes", []) if c.get("status") == "unaffected" and c.get("at")]
            if v.get("lessThan"):
                afectadas = f"{ini} → anteriores a {v['lessThan']}" if ini else f"Anteriores a {v['lessThan']}"
                corregida = " / ".join(arreglos) if arreglos else v["lessThan"]
            elif v.get("lessThanOrEqual"):
                afectadas = f"{ini} → {v['lessThanOrEqual']} (incluida)" if ini else f"Hasta {v['lessThanOrEqual']} (incluida)"
                corregida = " / ".join(arreglos) if arreglos else f"Posterior a {v['lessThanOrEqual']}"
            else:
                afectadas = ini or "Todas"
                corregida = " / ".join(arreglos) if arreglos else "Consultar aviso"
            fila = (producto, afectadas, corregida)
            if fila not in vistos:
                vistos.add(fila)
                filas.append({"producto": producto, "afectadas": afectadas, "corregida": corregida})
    return filas


def _versiones_nvd(cve):
    """Plan B: rangos de versiones de las CPE de NVD."""
    filas, vistos = [], set()
    for conf in cve.get("configurations", []):
        for nodo in conf.get("nodes", []):
            for m in nodo.get("cpeMatch", []):
                if m.get("vulnerable") is False:
                    continue
                partes = m.get("criteria", "").split(":")
                if len(partes) < 6:
                    continue
                producto = partes[4].replace("_", " ").title()
                ini = m.get("versionStartIncluding") or m.get("versionStartExcluding") or ""
                if m.get("versionEndExcluding"):
                    afectadas = f"{ini} → anteriores a {m['versionEndExcluding']}" if ini else f"Anteriores a {m['versionEndExcluding']}"
                    corregida = m["versionEndExcluding"]
                elif m.get("versionEndIncluding"):
                    afectadas = f"{ini} → {m['versionEndIncluding']} (incluida)" if ini else f"Hasta {m['versionEndIncluding']} (incluida)"
                    corregida = f"Posterior a {m['versionEndIncluding']}"
                elif partes[5] not in ("*", "-"):
                    afectadas, corregida = partes[5], "Consultar aviso"
                else:
                    continue
                fila = (producto, afectadas, corregida)
                if fila not in vistos:
                    vistos.add(fila)
                    filas.append({"producto": producto, "afectadas": afectadas, "corregida": corregida})
    return filas


def _textos(lista):
    return [" ".join(x.get("value", "").split()) for x in lista or [] if x.get("lang", "en").startswith("en") and x.get("value")]


def descargar_cna(ids, ruta_cache):
    """Registros oficiales de CVE.org (datos del fabricante). Caché de 12 h por CVE."""
    cache = {}
    if ruta_cache and os.path.exists(ruta_cache):
        try:
            with open(ruta_cache, encoding="utf-8") as f:
                cache = json.load(f)
        except (OSError, ValueError):
            cache = {}
    ahora = time.time()
    pendientes = [i for i in ids if i not in cache or ahora - cache[i]["t"] > 12 * 3600]

    def bajar(cve_id):
        try:
            d = http_json(CVE_ORG_URL + cve_id, intentos=2)
            cna = d.get("containers", {}).get("cna", {})
            return cve_id, {"t": ahora, "affected": cna.get("affected", []),
                            "configurations": cna.get("configurations", []), "solutions": cna.get("solutions", []),
                            "workarounds": cna.get("workarounds", []),
                            "references": [r.get("url") for r in cna.get("references", [])][:6]}
        except Exception as e:
            print(f"  ! CVE.org {cve_id}: {e}", file=sys.stderr)
            return cve_id, None

    if pendientes:
        print(f"  CVE.org: descargando detalle de {len(pendientes)} CVEs…", file=sys.stderr)
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(8) as ex:
            for cve_id, datos in ex.map(bajar, pendientes):
                if datos:
                    cache[cve_id] = datos
        if ruta_cache:
            with open(ruta_cache, "w", encoding="utf-8") as f:
                json.dump(cache, f)
    return cache


def _producto_valido(nombre):
    """Algunos fabricantes ponen 'n/a' o similar como nombre de producto en CVE.org."""
    return bool(nombre) and nombre.strip().lower() not in ("n/a", "na", "unknown", "unspecified", "*", "-")


def enriquecer(res, cves_por_id, ruta_cache):
    cna = descargar_cna([r["cve"] for r in res], ruta_cache)
    for r in res:
        c = cna.get(r["cve"], {})
        cve = cves_por_id[r["cve"]]
        r["requisitos"], r["resumen_explotacion"] = requisitos(r["vector"])
        r["versiones"] = _lineas_versiones(c.get("affected")) or _versiones_nvd(cve)
        productos = list(dict.fromkeys(a["product"] for a in c.get("affected", []) if _producto_valido(a.get("product"))))
        if not productos:
            productos = list(dict.fromkeys(p.split(":")[4].replace("_", " ").title()
                                           for p in cpes(cve) if p.count(":") > 4))
        r["producto"] = ", ".join(productos) or "Producto no especificado"
        for v in r["versiones"]:
            if not _producto_valido(v["producto"].split(" (")[0]):
                v["producto"] = r["producto"]
        r["condiciones"] = _textos(c.get("configurations"))
        r["solucion"] = _textos(c.get("solutions")) + [f"Mitigación: {t}" for t in _textos(c.get("workarounds"))]
        refs = c.get("references") or [x["url"] for x in cve.get("references", [])]
        r["aviso"] = refs[0] if refs else ""


# ----------------------------------------------------------------------------- salida

COLORES = {"CRITICAL": "\033[95m", "HIGH": "\033[91m", "MEDIUM": "\033[93m", "LOW": "\033[92m"}


def imprimir(res, kev_nuevos, dias):
    color = sys.stdout.isatty() and os.name != "nt" or os.environ.get("WT_SESSION")
    rst = "\033[0m" if color else ""
    print(f"\n=== Vulnerabilidades en seguridad perimetral publicadas en los últimos {dias} días: {len(res)} ===\n")
    for r in res:
        c = COLORES.get(r["severidad"], "") if color else ""
        score = f"{r['cvss']:.1f}" if r["cvss"] is not None else " -- "
        kev = "  [EXPLOTADA - CISA KEV]" if r["explotada_kev"] else ""
        print(f"{c}{r['cve']:<16} {score:>4} {r['severidad']:<11}{rst} {r['publicado']}  {r['fabricante']} · {r['producto']}{kev}")
        desc = " ".join(r["descripcion"].split())
        print(f"    {desc[:220]}{'…' if len(desc) > 220 else ''}")
    if kev_nuevos:
        print(f"\n=== Añadidas a CISA KEV (explotación activa) en el periodo: {len(kev_nuevos)} ===\n")
        for v in kev_nuevos:
            print(f"{v['cveID']:<16} {v['dateAdded']}  {v['vendorProject']} {v['product']} — {v['vulnerabilityName']}")


def guardar_csv(res, ruta):
    with open(ruta, "w", newline="", encoding="utf-8-sig") as f:  # utf-8-sig para que Excel lo abra bien
        campos = list(dict.fromkeys(k for r in res for k in r)) or ["cve"]
        w = csv.DictWriter(f, fieldnames=campos, delimiter=";", restval="")
        w.writeheader()
        for r in res:
            fila = dict(r)
            fila["requisitos"] = " | ".join(f"{k}: {v}" for k, v in r.get("requisitos", []))
            fila["versiones"] = " | ".join(f"{v['producto']} {v['afectadas']} -> {v['corregida']}" for v in r.get("versiones", []))
            fila["condiciones"] = " ".join(r.get("condiciones", []))
            fila["solucion"] = " ".join(r.get("solucion", []))
            w.writerow(fila)
    print(f"CSV guardado en {ruta}", file=sys.stderr)


PLANTILLA_HTML = r"""<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Informe Vulnerabilidades</title>
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Cpath d='M16 2.5 4.5 6.8v8.4c0 7.3 4.9 12.6 11.5 14.3 6.6-1.7 11.5-7 11.5-14.3V6.8z' fill='%23111827'/%3E%3Cpath d='m10.5 16.2 3.7 3.7 7.3-7.6' fill='none' stroke='%23fff' stroke-width='2.6' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E">
<meta name="theme-color" content="#f7f8fa">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Instrument+Serif:ital@0;1&family=Geist:wght@400;500;600&display=swap" rel="stylesheet">
<style>
/* Concepto: dossier de avisos de seguridad. Cada fabricante es un capítulo: el nombre en serif a la
   izquierda (fijo al hacer scroll) y sus CVEs a la derecha, separados por líneas finas. El color se
   reserva para la severidad y la explotación activa. Tema claro siempre; el oscuro solo con el botón. */
:root{
  --paper:#f7f8fa; --sheet:#ffffff; --ink:#111827; --text:#374151; --muted:#6b7280; --faint:#9ca3af;
  --rule:#e5e7eb; --rule-strong:#d1d5db; --wash:#f3f4f6; --accent:#1e3a8a;
  --crit:#86198f; --high:#c2410c; --med:#a16207; --low:#3f6212; --none:#6b7280;
  --exploit:#dc2626; --exploit-wash:#fef2f2; --fix:#047857; --fix-wash:#ecfdf5;
  --f-display:"Instrument Serif",Georgia,"Times New Roman",serif;
  --f-body:"Geist",system-ui,-apple-system,"Segoe UI",sans-serif;
  color-scheme:light;
}
:root[data-theme="dark"]{
  --paper:#0d1017; --sheet:#121620; --ink:#f3f4f6; --text:#d1d5db; --muted:#9ca3af; --faint:#6b7280;
  --rule:#232937; --rule-strong:#323a4b; --wash:#171c27; --accent:#93b4ff;
  --crit:#e879f9; --high:#fb923c; --med:#facc15; --low:#a3e635; --none:#9ca3af;
  --exploit:#f87171; --exploit-wash:#2a1416; --fix:#34d399; --fix-wash:#0f2a21;
  color-scheme:dark;
}
*{box-sizing:border-box}
[hidden]{display:none!important}
html,body{margin:0}
html{scroll-behavior:smooth}
@media (prefers-reduced-motion:reduce){html{scroll-behavior:auto}*{animation:none!important;transition:none!important}}
body{background:var(--paper);color:var(--text);font:15px/1.6 var(--f-body);-webkit-font-smoothing:antialiased;font-feature-settings:"ss01"}
.wrap{max-width:1180px;margin:0 auto;padding-inline:clamp(16px,4vw,48px)}
a{color:inherit}
svg.i{width:15px;height:15px;flex:none;stroke:currentColor;fill:none;stroke-width:1.7;stroke-linecap:round;stroke-linejoin:round}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:4px}
.mono{font-variant-numeric:tabular-nums}

/* ---------- cabecera ---------- */
.masthead{padding-block:56px 0}
.mrow{display:flex;justify-content:flex-end;align-items:flex-start;gap:16px;flex-wrap:wrap}
h1{font:400 clamp(44px,7vw,84px)/.95 var(--f-display);letter-spacing:-.02em;color:var(--ink);margin:22px 0 0;text-wrap:balance}
h1 em{font-style:italic;color:var(--muted)}
.meta-r{display:flex;align-items:center;gap:10px}
.status{display:inline-flex;align-items:center;gap:8px;font:500 12px/1 var(--f-body);color:var(--muted);border:1px solid var(--rule-strong);border-radius:999px;padding:8px 12px;background:var(--sheet)}
.status .dot{width:7px;height:7px;border-radius:50%;background:var(--fix)}
.status.busy .dot{background:var(--med);animation:pulse 1s ease-in-out infinite}
@keyframes pulse{50%{opacity:.25}}
.ghost{display:inline-grid;place-items:center;width:34px;height:34px;border-radius:999px;border:1px solid var(--rule-strong);background:var(--sheet);color:var(--muted);cursor:pointer}
.ghost:hover{color:var(--ink);border-color:var(--ink)}

/* índice: tabla de contenidos del dossier */
/* pestañas de vista y selector de periodo */
.views{display:flex;justify-content:space-between;align-items:flex-end;gap:12px 24px;flex-wrap:wrap;margin-top:32px}
.tabs{display:flex;gap:28px}
.tabs button{background:none;border:0;border-bottom:2px solid transparent;padding:4px 0 8px;font:500 15px var(--f-body);color:var(--muted);cursor:pointer}
.tabs button:hover{color:var(--ink)}
.tabs button[aria-selected="true"]{color:var(--ink);border-color:var(--ink)}
.range{display:flex;align-items:center;gap:10px;flex-wrap:wrap;font-size:13.5px;color:var(--muted);padding-bottom:8px}
.presets{display:flex;gap:4px;flex-wrap:wrap}
.presets button,.range input[type=date]{border:1px solid var(--rule-strong);background:var(--sheet);color:var(--text);border-radius:999px;padding:5px 12px;font:inherit;font-size:13px;cursor:pointer}
.presets button:hover{border-color:var(--ink)}
.presets button.on{background:var(--ink);border-color:var(--ink);color:var(--sheet)}

/* índice: una sola fila de fabricantes entre dos líneas a todo el ancho */
.toc{display:flex;flex-wrap:wrap;align-items:baseline;gap:10px 48px;margin-top:0;padding-block:16px;border-top:1px solid var(--ink);border-bottom:1px solid var(--ink)}
.toc a{display:inline-flex;align-items:baseline;gap:10px;text-decoration:none;color:var(--ink)}
.toc a:hover .tn{color:var(--accent)}
.toc .tc{font:500 11px var(--f-body);color:var(--faint)}
.toc .tn{font:400 22px/1.15 var(--f-display);transition:color .15s;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.toc .tq{font:500 12px var(--f-body);color:var(--muted);white-space:nowrap}
.toc .tq .x{color:var(--exploit)}

/* ---------- herramientas ---------- */
.tools{position:sticky;top:0;z-index:5;background:color-mix(in srgb,var(--paper) 90%,transparent);backdrop-filter:saturate(1.2) blur(10px);border-bottom:1px solid var(--rule)}
.tb{display:flex;flex-wrap:wrap;align-items:center;gap:8px 20px;padding-block:12px}
.search{flex:1 1 200px;display:flex;align-items:center;gap:10px;color:var(--faint);border-bottom:1px solid var(--rule-strong);padding:6px 2px}
.search:focus-within{border-color:var(--ink);color:var(--ink)}
.search input{flex:1;min-width:0;border:0;background:transparent;font:inherit;font-size:14.5px;color:var(--ink);outline:none}
.search input::placeholder{color:var(--faint)}
.opt{display:inline-flex;align-items:center;gap:8px;font-size:13.5px;color:var(--text);cursor:pointer;user-select:none}
.opt input{appearance:none;margin:0;width:15px;height:15px;border:1px solid var(--rule-strong);border-radius:4px;display:grid;place-items:center;cursor:pointer;background:var(--sheet)}
.opt input:checked{background:var(--exploit);border-color:var(--exploit)}
.opt input:checked::after{content:"";width:7px;height:4px;border:1.6px solid #fff;border-top:0;border-right:0;transform:rotate(-45deg) translate(1px,-1px)}
.link{background:none;border:0;padding:0;font:inherit;font-size:13.5px;color:var(--text);cursor:pointer;text-decoration:underline;text-decoration-color:var(--rule-strong);text-underline-offset:4px}
.link:hover{color:var(--ink);text-decoration-color:var(--ink)}
/* Mis fabricantes: lista desplegable discreta */
.mf{position:relative}
.mf-panel{position:absolute;top:calc(100% + 12px);left:-16px;z-index:20;width:270px;background:var(--sheet);border:1px solid var(--rule-strong);
  border-radius:12px;box-shadow:0 14px 34px rgba(17,24,39,.12);padding:14px 16px}
.mf-panel h5{margin:0 0 6px;font:500 10.5px var(--f-body);letter-spacing:.12em;text-transform:uppercase;color:var(--muted)}
.mf-list{display:grid;max-height:300px;overflow:auto}
.mf-list label{display:flex;align-items:center;gap:10px;padding:5px 0;font-size:14px;color:var(--ink);cursor:pointer}
.mf-list input{accent-color:var(--ink);margin:0}
.mf-foot{display:flex;justify-content:space-between;margin-top:8px;padding-top:10px;border-top:1px solid var(--rule)}
.tb select{font:inherit;font-size:13px;color:var(--text);background:transparent;border:1px solid var(--rule-strong);border-radius:999px;padding:6px 10px;cursor:pointer}
.go{display:inline-flex;align-items:center;gap:8px;font:500 13.5px var(--f-body);color:var(--sheet);background:var(--ink);border:0;border-radius:999px;padding:8px 16px;cursor:pointer}
.go:hover{background:var(--accent)}
.go:disabled{opacity:.6;cursor:progress}
.go:disabled svg{animation:spin 1s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.estado{margin:0;padding-bottom:10px;font:12px var(--f-body);color:var(--muted)}
.estado:empty{display:none}

/* ---------- capítulo por fabricante ---------- */
.vendor{padding-block:56px;scroll-margin-top:72px}
.vside{display:flex;align-items:baseline;gap:16px;margin-bottom:28px}
.vno{font:500 11px var(--f-body);letter-spacing:.14em;color:var(--faint)}
.vside h2{font:400 clamp(36px,5vw,52px)/1 var(--f-display);color:var(--ink);margin:0;letter-spacing:-.01em;text-wrap:balance}

/* producto */
.product + .product{margin-top:40px}
.phead{display:flex;align-items:baseline;justify-content:space-between;gap:12px;padding-bottom:10px;border-bottom:1px solid var(--ink)}
.phead h3{margin:0;font:600 16px/1.3 var(--f-body);color:var(--ink)}
.phead span{font:500 11.5px var(--f-body);color:var(--muted);letter-spacing:.06em;text-transform:uppercase}

/* ---------- CVE ---------- */
.cve{border-bottom:1px solid var(--rule)}
.cve>summary{list-style:none;cursor:pointer;display:grid;grid-template-columns:92px minmax(0,1fr) auto;gap:20px;align-items:start;padding:18px 0}
.cve>summary::-webkit-details-marker{display:none}
.cve>summary:hover .cid{color:var(--accent)}
.sc{display:flex;flex-direction:column;gap:6px}
.sc b{font:600 26px/1 var(--f-body);color:var(--c);font-variant-numeric:tabular-nums;letter-spacing:-.02em}
.sc small{font:600 10px/1 var(--f-body);letter-spacing:.12em;text-transform:uppercase;color:var(--c)}
/* escala CVSS de 0 a 10: diez marcas, rellenas hasta la puntuación */
.ticks{display:grid;grid-template-columns:repeat(10,1fr);gap:2px;width:80px}
.ticks i{height:4px;border-radius:1px;background:var(--rule)}
.ticks i.on{background:var(--c)}
.cmain{min-width:0}
.cline{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.cid{font:600 15px var(--f-body);color:var(--ink);font-variant-numeric:tabular-nums;transition:color .15s}
.flag{display:inline-flex;align-items:center;gap:6px;font:600 10.5px/1 var(--f-body);letter-spacing:.1em;text-transform:uppercase;color:var(--exploit);background:var(--exploit-wash);padding:5px 8px;border-radius:999px}
.flag::before{content:"";width:6px;height:6px;border-radius:50%;background:currentColor}
.flag.kev::before{animation:pulse 1.6s ease-in-out infinite}
.flag.new{color:var(--fix);background:var(--fix-wash)}
.excerpt{margin:6px 0 0;color:var(--text);font-size:14.5px;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;max-width:72ch}
.cve[open] .excerpt{display:none}
.cright{display:grid;grid-template-columns:auto auto;align-items:center;justify-items:end;gap:8px 14px;font:12px var(--f-body);color:var(--muted);white-space:nowrap;padding-top:4px}
.plus{width:22px;height:22px;border:1px solid var(--rule-strong);border-radius:50%;display:grid;place-items:center;color:var(--muted);transition:transform .2s,border-color .2s}
.cve>summary:hover .plus{border-color:var(--ink);color:var(--ink)}
.cve[open] .plus{transform:rotate(45deg)}
.copy{grid-column:2;width:22px;height:22px;border:1px solid var(--rule-strong);border-radius:50%;display:grid;place-items:center;
  color:var(--muted);background:transparent;padding:0;cursor:pointer;position:relative;transition:border-color .2s,color .2s}
.copy svg.i{width:12px;height:12px}
.copy:hover{border-color:var(--ink);color:var(--ink)}
.copy.ok{border-color:var(--fix);color:var(--fix)}
.copy::after{content:attr(data-msg);position:absolute;right:30px;top:50%;transform:translateY(-50%);font:500 11.5px var(--f-body);
  color:var(--sheet);background:var(--ink);padding:4px 8px;border-radius:6px;white-space:nowrap;opacity:0;pointer-events:none;transition:opacity .15s}
.copy:hover::after,.copy.ok::after{opacity:1}

.body{margin-left:112px;padding-bottom:30px;display:grid;gap:26px}
.sec{display:grid;grid-template-columns:120px minmax(0,1fr);gap:20px}
.sec>h4{margin:0;font:500 11px/1.9 var(--f-body);letter-spacing:.12em;text-transform:uppercase;color:var(--muted)}
.sec>div{min-width:0}
.desc{margin:0;color:var(--ink);font-size:15px;line-height:1.7;max-width:68ch}
.verdict{margin:0 0 14px;font:600 16.5px/1.45 var(--f-body);color:var(--ink);text-wrap:balance}
.spec{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:0 24px;margin:0}
.spec div{display:flex;flex-direction:column;gap:3px;padding:10px 0 12px;border-top:1px solid var(--rule)}
.spec dt{font:500 10.5px var(--f-body);letter-spacing:.1em;text-transform:uppercase;color:var(--muted)}
.spec dd{margin:0;font-size:14px;font-weight:500;color:var(--ink);line-height:1.4}
.spec .worst dd{color:var(--exploit)}
.spec .worst dd::before{content:"●";font-size:8px;vertical-align:2px;margin-right:6px}
.cond{margin:16px 0 0;padding-left:14px;border-left:2px solid var(--med);color:var(--text);font-size:14px;max-width:68ch}
.cond b{color:var(--ink);font-weight:600}
.tblwrap{overflow-x:auto}
table.vtable{border-collapse:collapse;width:100%;font-size:13.5px;background:var(--sheet)}
.vtable th,.vtable td{border:1px solid var(--rule-strong);padding:10px 14px;text-align:left;vertical-align:middle}
.vtable th{font:500 10.5px var(--f-body);letter-spacing:.12em;text-transform:uppercase;color:var(--muted);background:var(--wash)}
.vtable td{color:var(--ink)}
.vtable td.mono{white-space:nowrap}
.vtable td.fx{color:var(--fix);font-weight:600}
.vtable td.fx::before{content:"↑ ";color:var(--fix)}
.nota{margin:12px 0 0;font-size:13.5px;color:var(--muted);max-width:68ch}
/* ¿Me afecta? */
.check{display:flex;flex-wrap:wrap;align-items:center;gap:8px 12px;margin-top:14px;font-size:13.5px;color:var(--muted)}
.check input{font:inherit;font-size:13.5px;color:var(--ink);background:var(--sheet);border:1px solid var(--rule-strong);border-radius:999px;padding:5px 12px;width:150px}
.check input:focus{outline:none;border-color:var(--ink)}
.check output{font-weight:500;color:var(--text)}
.check output.si{color:var(--exploit)} .check output.no{color:var(--fix)}
/* enlace directo: resalta un momento la CVE abierta */
.cve.foco{animation:foco 2.6s ease-out}
@keyframes foco{0%,45%{background:var(--wash)}100%{background:transparent}}
.refs{display:flex;flex-wrap:wrap;gap:10px 22px;align-items:center;font-size:13.5px}
.refs a{display:inline-flex;align-items:center;gap:6px;color:var(--ink);text-decoration:underline;text-decoration-color:var(--rule-strong);text-underline-offset:4px}
.refs a:hover{color:var(--accent);text-decoration-color:currentColor}
.refs span{font:12px var(--f-body);color:var(--muted)}
.spec .pct{color:var(--muted);font-weight:400}
.refs .due{color:var(--exploit)}
.empty{padding:80px 0;text-align:center;font-size:16px;color:var(--muted)}

.s-CRITICAL{--c:var(--crit)} .s-HIGH{--c:var(--high)} .s-MEDIUM{--c:var(--med)} .s-LOW{--c:var(--low)} .s-NONE{--c:var(--none)}

footer{padding-block:40px 64px;display:flex;justify-content:space-between;gap:16px;flex-wrap:wrap;font:12px var(--f-body);color:var(--faint)}

@media (max-width:900px){.vendor{padding-block:40px}}
@media (max-width:640px){
  .cve>summary{grid-template-columns:72px minmax(0,1fr);gap:14px}
  /* en móvil: fecha, «+» y «copiar» en una sola fila bajo el texto */
  .cright{grid-column:2;padding-top:0;grid-template-columns:auto auto auto;justify-content:start;justify-items:start}
  .copy{grid-column:auto}
  .copy::after{right:auto;left:30px}
  .body{margin-left:0} .sec{grid-template-columns:minmax(0,1fr);gap:8px}
  .spec{grid-template-columns:repeat(2,minmax(0,1fr));gap:0 16px}
  .masthead{padding-block:28px 0}
  .views{margin-top:24px}
  /* barra de herramientas: no fija (ocuparía media pantalla) y ordenada en cuadrícula */
  .tools{position:static;backdrop-filter:none}
  .tb{display:grid;grid-template-columns:1fr 1fr;gap:14px 16px;align-items:center}
  .tb>*{justify-self:start}
  .tb>.search{grid-column:1/-1;justify-self:stretch}
  .go{justify-self:end}
  .tb{position:relative}
  .mf{position:static}
  .mf-panel{left:0;right:0;width:auto;top:calc(100% + 4px)}
  .check input{width:100%}
}
</style></head>
<body>
<header class="wrap masthead">
  <div class="mrow">
    <div class="meta-r">
      <span class="status" id="status"><span class="dot"></span><span id="statustxt"></span></span>
      <button class="ghost" id="theme" title="Cambiar a tema oscuro" aria-label="Cambiar tema"><svg class="i" viewBox="0 0 24 24"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8Z"/></svg></button>
    </div>
  </div>
  <h1>Informe <em>Vulnerabilidades</em></h1>
  <div class="views">
    <div class="tabs" role="tablist" aria-label="Vista">
      <button role="tab" id="tab-rec" aria-selected="true"></button>
      <button role="tab" id="tab-per" aria-selected="false">Por periodo</button>
    </div>
    <div class="range" id="range" hidden>
      <span>Desde</span>
      <div class="presets" id="presets">
        <button data-d="30">30 días</button><button data-d="90">90 días</button><button data-d="182">6 meses</button><button data-d="365">1 año</button>
      </div>
      <input type="date" id="desde" aria-label="Fecha de inicio">
      <span>hasta hoy</span>
    </div>
  </div>
  <nav class="toc" id="index"></nav>
</header>

<div class="tools"><div class="wrap">
  <div class="tb">
    <label class="search"><svg class="i" viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/></svg>
      <input type="search" id="q" placeholder="Buscar por CVE, producto o versión" autocomplete="off"></label>
    <label class="opt"><input type="checkbox" id="kev"> Solo explotadas</label>
    <span class="mf">
      <button class="link" id="mf-btn" aria-expanded="false" aria-controls="mf-panel">Mis fabricantes</button>
      <div class="mf-panel" id="mf-panel" hidden>
        <h5>Mostrar solo</h5>
        <div class="mf-list" id="mf-list"></div>
        <div class="mf-foot"><button class="link" id="mf-todos">Ver todos</button><button class="link" id="mf-cerrar">Listo</button></div>
      </div>
    </span>
    <button class="link" id="toggle">Expandir todo</button>
    <button class="link" id="export">Exportar a Excel</button>
    <select id="auto" aria-label="Actualización automática" title="Actualización automática">
      <option value="0">Auto: no</option><option value="15">Auto: 15 min</option><option value="30">Auto: 30 min</option>
      <option value="60">Auto: 1 h</option><option value="120">Auto: 2 h</option><option value="360">Auto: 6 h</option>
    </select>
    <button class="go" id="refresh"><svg class="i" viewBox="0 0 24 24"><path d="M21 12a9 9 0 1 1-2.6-6.4"/><path d="M21 4v5h-5"/></svg>Actualizar</button>
  </div>
  <p class="estado" id="estado"></p>
</div></div>

<main class="wrap" id="main"></main>
<footer class="wrap"><span>Fuentes: NVD (NIST) · CVE.org · CISA KEV</span></footer>
<script>
// Datos generados por vulns_perimetrales.py: todas las CVEs del periodo cubierto (por defecto 30 días)
const CONFIG = __CONFIG__;
const SEV = {CRITICAL:"Crítica",HIGH:"Alta",MEDIUM:"Media",LOW:"Baja"};
const sk = s => SEV[s] ? s : "NONE";
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const $ = id => document.getElementById(id);
const slug = s => s.toLowerCase().normalize("NFD").replace(/[^a-z0-9]+/g,"-");
const fecha = d => new Date(d+"T00:00:00").toLocaleDateString("es-ES",{day:"numeric",month:"short",year:"numeric"});
const fechaHora = d => new Date(d).toLocaleString("es-ES",{day:"2-digit",month:"2-digit",year:"numeric",hour:"2-digit",minute:"2-digit"});
const PEOR = ["Red (remoto)","Ninguno (sin autenticación)","No necesaria","Baja","Ninguna"];
const prio = r => (r.explotada_kev ? 100 : 0) + (r.cvss || 0);
const store = {
  get(k){ try { return JSON.parse(localStorage.getItem(k)); } catch(e) { return null; } },
  set(k,v){ try { localStorage.setItem(k, JSON.stringify(v)); return true; } catch(e) { return false; } },
};
const CLAVE = "vp-archivo-v2-" + Object.keys(CONFIG.fabricantes).sort().join(",") + "-" + CONFIG.min_cvss + (CONFIG.solo_kev ? "-kev" : "");
const MAX_DIAS = 365;   // el panel «Por periodo» permite ir como mucho un año atrás
const isoDia = d => new Date(d).toISOString().slice(0, 10);
const haceDias = n => isoDia(Date.now() - n * 864e5);

// Archivo: lo que trae el HTML combinado con lo que este navegador haya descargado después
let estado = {desde: CONFIG.cubre_desde, hasta: CONFIG.generado, completa: CONFIG.generado, data: __DATA__};
const guardado = store.get(CLAVE);
if (guardado && Array.isArray(guardado.data)) {
  const [viejo, nuevo] = guardado.hasta > estado.hasta ? [estado, guardado] : [guardado, estado];
  const m = new Map(viejo.data.map(r => [r.cve, r]));
  nuevo.data.forEach(r => m.set(r.cve, r));
  estado = {desde: viejo.desde < nuevo.desde ? viejo.desde : nuevo.desde, hasta: nuevo.hasta,
            completa: viejo.completa > nuevo.completa ? viejo.completa : nuevo.completa, data: [...m.values()]};
}
// Si con el histórico largo no cabe en el navegador, se guarda solo lo del periodo base (el resto se recarga del archivo)
const guardar = () => {
  if (store.set(CLAVE, estado)) return;
  const base = CONFIG.cubre_desde > estado.desde ? CONFIG.cubre_desde : estado.desde;
  if (!store.set(CLAVE, {...estado, desde: base, data: estado.data.filter(r => r.publicado >= isoDia(base))}))
    console.warn("No cabe el estado en el almacenamiento del navegador");
};

// Vista: «Últimos N días» o «Por periodo» (desde una fecha elegida hasta hoy)
let vista = store.get("vp-vista") === "periodo" ? "periodo" : "recientes";
let desdeSel = store.get("vp-desde") || haceDias(30);
if (desdeSel < haceDias(MAX_DIAS)) desdeSel = haceDias(MAX_DIAS);
const corteVista = () => vista === "recientes" ? isoDia(new Date(estado.hasta) - CONFIG.dias * 864e5) : desdeSel;
// «Mis fabricantes»: si hay alguno marcado, solo se muestran esos (se recuerda en este navegador)
const MARCAS = new Set(Object.values(CONFIG.fabricantes).map(f => f.nombre));
let misFab = new Set((store.get("vp-mis") || []).filter(n => MARCAS.has(n)));
let forzada = null;   // CVE abierta por enlace directo: se muestra aunque los filtros la ocultaran
const datosVista = () => {
  const c = corteVista();
  return estado.data.filter(r => r.cve === forzada || (r.publicado >= c && (!misFab.size || misFab.has(r.fabricante))));
};

// tema: siempre claro salvo que el usuario elija el oscuro con el botón
const root = document.documentElement;
if (store.get("vp-theme2") === "dark") root.dataset.theme = "dark";
$("theme").onclick = () => {
  const oscuro = root.dataset.theme !== "dark";
  if (oscuro) root.dataset.theme = "dark"; else delete root.dataset.theme;
  store.set("vp-theme2", oscuro ? "dark" : "light");
};

// ---------------------------------------------------------------- pintado
const ICO = {
  ext:  '<path d="M7 17 17 7M8 7h9v9"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  copy: '<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15H4a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v1"/>',
  ok:   '<path d="m5 12 5 5 9-10"/>',
};
const ico = k => `<svg class="i" viewBox="0 0 24 24">${ICO[k]}</svg>`;
const extracto = t => t.trim().split(/(?<=\.)\s/)[0];
const ticks = v => `<span class="ticks">${Array.from({length:10}, (_, i) => `<i class="${v != null && v > i ? "on" : ""}"></i>`).join("")}</span>`;
const NOMBRES = {CRITICAL:["Crítica","Críticas"],HIGH:["Alta","Altas"],MEDIUM:["Media","Medias"],LOW:["Baja","Bajas"],NONE:["Sin puntuar","Sin puntuar"]};

function bloque(r){
  const s = sk(r.severidad);
  const epss = r.epss != null
    ? `<div class="${r.epss >= 0.1 ? "worst" : ""}" title="Probabilidad de que se explote en los próximos 30 días (EPSS, FIRST.org)"><dt>Prob. de explotación</dt>
       <dd>${(r.epss * 100).toLocaleString("es-ES", {maximumFractionDigits: r.epss < 0.01 ? 2 : 1})} %<span class="pct"> · percentil ${Math.round(r.epss_pct * 100)}</span></dd></div>`
    : "";
  const reqs = r.requisitos.length
    ? `<p class="verdict">${esc(r.resumen_explotacion)}</p>
       <dl class="spec">${r.requisitos.map(([k,v]) => `<div class="${PEOR.includes(v)?"worst":""}"><dt>${esc(k)}</dt><dd>${esc(v)}</dd></div>`).join("")}${epss}</dl>`
    : `<p class="nota">El fabricante aún no ha publicado la métrica CVSS.</p>${epss ? `<dl class="spec">${epss}</dl>` : ""}`;
  const cond = r.condiciones.length ? `<p class="cond"><b>Condiciones.</b> ${esc(r.condiciones.join(" "))}</p>` : "";
  const vers = r.versiones.length
    ? `<div class="tblwrap"><table class="vtable"><thead><tr><th>Producto</th><th>Versiones afectadas</th><th>Actualizar a</th></tr></thead><tbody>${
        r.versiones.map(v => `<tr><td>${esc(v.producto)}</td><td class="mono">${esc(v.afectadas)}</td><td class="mono fx">${esc(v.corregida)}</td></tr>`).join("")
      }</tbody></table></div>`
    : `<p class="nota">Sin datos de versiones estructurados. Consulta el aviso del fabricante.</p>`;
  const check = r.versiones.length
    ? `<div class="check"><label for="v-${esc(r.cve)}">¿Me afecta? Tu versión</label>
         <input id="v-${esc(r.cve)}" data-ver="${esc(r.cve)}" placeholder="p. ej. 7.4.3" autocomplete="off" spellcheck="false"><output></output></div>`
    : "";
  const sol = r.solucion.length ? `<p class="nota">${esc(r.solucion.join(" "))}</p>` : "";
  return `<details class="cve s-${s}" data-id="${esc(r.cve)}" data-kev="${r.explotada_kev?1:0}" data-q="${esc([r.cve,r.fabricante,r.producto,r.descripcion,r.cwe,r.versiones.map(v=>v.afectadas+" "+v.corregida).join(" ")].join(" ").toLowerCase())}">
    <summary>
      <div class="sc"><b>${r.cvss != null ? Number(r.cvss).toFixed(1) : "—"}</b>${ticks(r.cvss)}<small>${SEV[s] || "Sin puntuar"}</small></div>
      <div class="cmain">
        <div class="cline"><span class="cid">${esc(r.cve)}</span>
          ${r.explotada_kev ? `<span class="flag kev">Explotada</span>` : ""}
          ${r.nueva ? `<span class="flag new">Nueva</span>` : ""}</div>
        <p class="excerpt">${esc(extracto(r.descripcion))}</p>
      </div>
      <div class="cright">${fecha(r.publicado)}<span class="plus">${ico("plus")}</span>
        <button class="copy" type="button" data-copiar="${esc(r.cve)}" data-msg="Copiar resumen" aria-label="Copiar resumen de ${esc(r.cve)}">${ico("copy")}</button></div>
    </summary>
    <div class="body">
      <section class="sec"><h4>Descripción</h4><div><p class="desc">${esc(r.descripcion.trim())}</p></div></section>
      <section class="sec"><h4>Explotación</h4><div>${reqs}${cond}</div></section>
      <section class="sec"><h4>Versiones</h4><div>${vers}${check}${sol}</div></section>
      <section class="sec"><h4>Referencias</h4><div class="refs">
        <a href="${esc(r.url)}" target="_blank" rel="noopener">NVD${ico("ext")}</a>
        ${r.aviso ? `<a href="${esc(r.aviso)}" target="_blank" rel="noopener">Aviso del fabricante${ico("ext")}</a>` : ""}
        ${r.cwe ? `<span>${esc(r.cwe)}</span>` : ""}
        <a href="#${esc(r.cve)}" class="enlace" data-enlace="${esc(r.cve)}">Copiar enlace directo</a>
        ${r.kev_fecha_limite ? `<span class="due">Límite CISA ${fecha(r.kev_fecha_limite)}</span>` : ""}
      </div></section>
    </div></details>`;
}

function render(){
  const abiertos = new Set([...document.querySelectorAll(".cve[open]")].map(d => d.dataset.id));
  const grupos = {};
  datosVista().forEach(r => ((grupos[r.fabricante] ??= {})[r.producto] ??= []).push(r));
  const fabs = Object.keys(grupos).map(f => {
    const todos = Object.values(grupos[f]).flat();
    return {f, todos, max: Math.max(...todos.map(prio))};
  }).sort((a,b) => b.max - a.max || b.todos.length - a.todos.length);
  const cuenta = (lista, k) => lista.filter(r => sk(r.severidad) === k).length;
  const num = i => String(i + 1).padStart(2, "0");

  $("statustxt").textContent = `Actualizado ${fechaHora(estado.hasta)}`;

  $("index").innerHTML = fabs.map(({f, todos}, i) => {
    const kevn = todos.filter(r => r.explotada_kev).length;
    return `<a href="#${slug(f)}"><span class="tc">${num(i)}</span><span class="tn">${esc(f)}</span>
      <span class="tq">${todos.length} CVE${todos.length>1?"s":""}${kevn ? ` · <span class="x">${kevn} expl.</span>` : ""}</span></a>`;
  }).join("");

  $("main").innerHTML = fabs.length ? fabs.map(({f}, i) => {
    const prods = Object.entries(grupos[f]).sort((a,b) => Math.max(...b[1].map(prio)) - Math.max(...a[1].map(prio)));
    return `<section class="vendor" id="${slug(f)}">
      <header class="vside"><span class="vno">${num(i)} / ${String(fabs.length).padStart(2, "0")}</span><h2>${esc(f)}</h2></header>
      <div>${prods.map(([p, rows]) => `<div class="product"><div class="phead"><h3>${esc(p)}</h3><span>${rows.length} CVE${rows.length>1?"s":""}</span></div>
        ${rows.sort((a,b)=>prio(b)-prio(a)).map(bloque).join("")}</div>`).join("")}</div>
    </section>`;
  }).join("") : `<p class="empty">${misFab.size ? "No hay vulnerabilidades de tus fabricantes en este periodo." : "No hay vulnerabilidades en este periodo."}</p>`;
  document.querySelectorAll(".cve").forEach(d => { if (abiertos.has(d.dataset.id)) d.open = true; });
  filtrar();
}

// filtros
function filtrar(){
  const q = $("q").value.toLowerCase().trim(), soloKev = $("kev").checked;
  document.querySelectorAll(".cve").forEach(d => d.hidden = (soloKev && d.dataset.kev !== "1") || (q && !d.dataset.q.includes(q)));
  document.querySelectorAll(".product").forEach(p => p.hidden = !p.querySelector(".cve:not([hidden])"));
  document.querySelectorAll(".vendor").forEach(v => v.hidden = !v.querySelector(".cve:not([hidden])"));
}
$("q").oninput = filtrar; $("kev").onchange = filtrar;

// ---------- Mis fabricantes
const nombresFab = Object.values(CONFIG.fabricantes).map(f => f.nombre).sort((a, b) => a.localeCompare(b, "es"));
function pintarMF(){
  $("mf-list").innerHTML = nombresFab.map(n => `<label><input type="checkbox" value="${esc(n)}"${misFab.has(n) ? " checked" : ""}>${esc(n)}</label>`).join("");
  $("mf-btn").textContent = misFab.size ? `Mis fabricantes · ${misFab.size}` : "Mis fabricantes";
}
function abrirMF(si){ $("mf-panel").hidden = !si; $("mf-btn").setAttribute("aria-expanded", String(si)); }
$("mf-btn").onclick = e => { e.stopPropagation(); abrirMF($("mf-panel").hidden); };
$("mf-list").onchange = e => {
  e.target.checked ? misFab.add(e.target.value) : misFab.delete(e.target.value);
  store.set("vp-mis", [...misFab]);
  $("mf-btn").textContent = misFab.size ? `Mis fabricantes · ${misFab.size}` : "Mis fabricantes";
  render();
};
$("mf-todos").onclick = () => { misFab.clear(); store.set("vp-mis", []); pintarMF(); render(); };
$("mf-cerrar").onclick = () => abrirMF(false);
document.addEventListener("click", e => { if (!e.target.closest(".mf")) abrirMF(false); });
document.addEventListener("keydown", e => { if (e.key === "Escape") abrirMF(false); });
pintarMF();

// ---------- ¿Me afecta? Compara la versión escrita con los rangos de la tabla de versiones
const numeros = t => (String(t).match(/\d+/g) || []).map(Number);
function comparar(a, b){
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const x = a[i] ?? -1, y = b[i] ?? -1;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}
function rango(t){
  let m;
  if ((m = t.match(/^(.+?)\s*→\s*anteriores a (.+)$/i))) return {ini: m[1], fin: m[2], incl: false};
  if ((m = t.match(/^anteriores a (.+)$/i))) return {fin: m[1], incl: false};
  if ((m = t.match(/^(.+?)\s*→\s*(.+?) \(incluida\)$/i))) return {ini: m[1], fin: m[2], incl: true};
  if ((m = t.match(/^hasta (.+?) \(incluida\)$/i))) return {fin: m[1], incl: true};
  if (/^todas$/i.test(t)) return {todas: true};
  return {exacta: t};
}
function meAfecta(r, texto){
  const v = numeros(texto);
  if (!v.length) return null;
  const coinciden = [];
  for (const fila of r.versiones) {
    const g = rango(fila.afectadas);
    let dentro;
    if (g.todas) dentro = true;
    else if (g.exacta) dentro = comparar(v, numeros(g.exacta)) === 0;
    else {
      const sobre = !g.ini || comparar(v, numeros(g.ini)) >= 0;
      const c = comparar(v, numeros(g.fin));
      dentro = sobre && (g.incl ? c <= 0 : c < 0);
    }
    if (dentro) {
      // se prefiere la fila de la misma rama (más números en común con la versión corregida)
      const f = numeros(g.fin || g.exacta || "");
      let comun = 0; while (comun < v.length && v[comun] === f[comun]) comun++;
      coinciden.push({fila, comun});
    }
  }
  coinciden.sort((a, b) => b.comun - a.comun);
  return coinciden.map(c => c.fila);
}
$("main").addEventListener("input", e => {
  const inp = e.target.closest("input[data-ver]");
  if (!inp) return;
  const r = estado.data.find(x => x.cve === inp.dataset.ver), out = inp.nextElementSibling;
  const filas = meAfecta(r, inp.value);
  out.className = "";
  if (filas === null) { out.textContent = inp.value.trim() ? "Escribe un número de versión" : ""; return; }
  if (!filas.length) { out.className = "no"; out.textContent = "No afectada según el fabricante"; return; }
  const f = filas[0], varias = new Set(r.versiones.map(x => x.producto)).size > 1;
  out.className = "si";
  out.textContent = `Afectada${varias ? ` (${f.producto})` : ""} → actualiza a ${f.corregida}`;
});

// ---------- Enlace directo a una CVE (…/#CVE-2026-12345)
async function abrirDesdeEnlace(){
  const m = location.hash.match(/^#(CVE-\d{4}-\d+)$/i);
  if (!m) return;
  const id = m[1].toUpperCase();
  let r = estado.data.find(x => x.cve === id);
  if (!r && CONFIG.archivo) { await cargarArchivo(); r = estado.data.find(x => x.cve === id); }
  if (!r) { estadoTxt(`${id} no está en el informe del último año.`); return; }
  forzada = id;
  $("q").value = ""; $("kev").checked = false;
  if (r.publicado < corteVista()) elegirDesde(r.publicado); else render();
  const d = document.querySelector(`.cve[data-id="${id}"]`);
  if (!d) return;
  d.open = true;
  d.scrollIntoView({block: "center", behavior: "smooth"});
  d.classList.remove("foco"); void d.offsetWidth; d.classList.add("foco");
}
window.addEventListener("hashchange", abrirDesdeEnlace);
$("main").addEventListener("click", async e => {
  const a = e.target.closest("a[data-enlace]");
  if (!a) return;
  e.preventDefault();
  const url = location.href.split("#")[0] + "#" + a.dataset.enlace;
  history.replaceState(null, "", "#" + a.dataset.enlace);
  let ok = true;
  try { await navigator.clipboard.writeText(url); } catch (err) { ok = false; }
  a.textContent = ok ? "Enlace copiado" : url;
  setTimeout(() => { a.textContent = "Copiar enlace directo"; }, 1800);
});

// ---------- Exportar a Excel (CSV con separador «;» y BOM, que Excel abre directamente)
$("export").onclick = () => {
  const q = $("q").value.toLowerCase().trim(), soloKev = $("kev").checked;
  const filas = datosVista()
    .filter(r => (!soloKev || r.explotada_kev) &&
      (!q || [r.cve, r.fabricante, r.producto, r.descripcion, r.cwe, r.versiones.map(v => v.afectadas + " " + v.corregida).join(" ")].join(" ").toLowerCase().includes(q)))
    .sort((a, b) => a.fabricante.localeCompare(b.fabricante) || a.producto.localeCompare(b.producto) || prio(b) - prio(a));
  const cab = ["Fabricante","Producto","CVE","CVSS","Severidad","Explotada (CISA KEV)","Prob. explotación EPSS (%)","Publicada",
               "Versiones afectadas","Actualizar a","Descripción","Aviso del fabricante","NVD"];
  const celda = v => { const t = String(v ?? ""); return /[";\n\r]/.test(t) ? `"${t.replace(/"/g, '""')}"` : t; };
  const lineas = [cab, ...filas.map(r => [
    r.fabricante, r.producto, r.cve, r.cvss != null ? String(r.cvss).replace(".", ",") : "", SEV[sk(r.severidad)] || "Sin puntuar",
    r.explotada_kev ? "Sí" : "No", r.epss != null ? (r.epss * 100).toFixed(2).replace(".", ",") : "", r.publicado,
    r.versiones.map(v => `${v.producto}: ${v.afectadas}`).join(" | "), [...new Set(r.versiones.map(v => v.corregida))].join(" | "),
    r.descripcion.replace(/\s+/g, " ").trim(), r.aviso || "", r.url,
  ])].map(f => f.map(celda).join(";"));
  const blob = new Blob(["\ufeff" + lineas.join("\r\n")], {type: "text/csv;charset=utf-8"});
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `vulnerabilidades_${corteVista()}_${isoDia(Date.now())}.csv`;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  estadoTxt(`Exportadas ${filas.length} CVE${filas.length === 1 ? "" : "s"}`);
};

// Copiar resumen de un CVE. Con formato (Outlook, Teams, Word) se pega así, con el nombre del aviso como enlace:
//   FortiMail: CVE-2026-104286
//   PSIRT | FortiGuard Labs   https://nvd.nist.gov/vuln/detail/CVE-2026-104286
// En texto plano el aviso lleva además su dirección, para no perder el enlace.
const PORTALES = {   // nombre del portal de avisos de cada fabricante, según el dominio del enlace
  "fortiguard.fortinet.com": "PSIRT | FortiGuard Labs",
  "security.paloaltonetworks.com": "Palo Alto Networks Security Advisories",
  "sec.cloudapps.cisco.com": "Cisco Security Advisory",
  "support.citrix.com": "Citrix Security Bulletin",
  "psirt.watchguard.com": "WatchGuard PSIRT",
  "support.checkpoint.com": "Check Point Security Advisory",
  "psirt.global.sonicwall.com": "SonicWall PSIRT",
  "supportportal.juniper.net": "Juniper Security Bulletin",
  "my.f5.com": "F5 Security Advisory",
  "hub.ivanti.com": "Ivanti Security Advisory",
  "forums.ivanti.com": "Ivanti Security Advisory",
  "www.sophos.com": "Sophos Security Advisory",
  "www.zyxel.com": "Zyxel Security Advisory",
  "advisories.stormshield.eu": "Stormshield Security Advisory",
  "support.forcepoint.com": "Forcepoint Security Advisory",
  "docs.netgate.com": "Netgate Security Advisory",
  "docs.opnsense.org": "OPNsense Security Advisory",
};
function nombreAviso(r){
  try { return PORTALES[new URL(r.aviso).hostname] || `Aviso de ${r.fabricante}`; }
  catch (e) { return `Aviso de ${r.fabricante}`; }
}
function resumenCVE(r){
  const titulo = `${r.producto}: ${r.cve}`;
  const nombre = r.aviso ? nombreAviso(r) : "";
  const texto = [titulo, r.aviso ? `${nombre} (${r.aviso})   ${r.url}` : r.url].join("\n");
  const a = (u, t) => `<a href="${esc(u)}">${esc(t)}</a>`;
  const htmlTxt = `<div style="font-family:Segoe UI,Helvetica,Arial,sans-serif;font-size:14px;line-height:1.6">${esc(titulo)}<br>`
    + (r.aviso ? `${a(r.aviso, nombre)}&nbsp;&nbsp;&nbsp;` : "") + `${a(r.url, r.url)}</div>`;
  return {texto, htmlTxt};
}
async function copiar({texto, htmlTxt}){
  try {
    if (window.ClipboardItem && navigator.clipboard?.write) {
      await navigator.clipboard.write([new ClipboardItem({
        "text/plain": new Blob([texto], {type: "text/plain"}),
        "text/html": new Blob([htmlTxt], {type: "text/html"}),
      })]);
      return true;
    }
    await navigator.clipboard.writeText(texto);
    return true;
  } catch (e) {
    // plan B: copia clásica con un cuadro de texto temporal
    const t = document.createElement("textarea");
    t.value = texto; t.style.position = "fixed"; t.style.opacity = "0";
    document.body.appendChild(t); t.select();
    const ok = document.execCommand("copy");
    t.remove();
    return ok;
  }
}
$("main").addEventListener("click", async ev => {
  const b = ev.target.closest(".copy");
  if (!b) return;
  ev.preventDefault(); ev.stopPropagation();   // que no abra/cierre el CVE
  const r = estado.data.find(x => x.cve === b.dataset.copiar);
  if (!r) return;
  const ok = await copiar(resumenCVE(r));
  b.classList.toggle("ok", ok);
  b.dataset.msg = ok ? "Copiado" : "No se pudo copiar";
  b.innerHTML = ico(ok ? "ok" : "copy");
  clearTimeout(b._t);
  b._t = setTimeout(() => { b.classList.remove("ok"); b.dataset.msg = "Copiar resumen"; b.innerHTML = ico("copy"); }, 1800);
});
let abierto = false;
$("toggle").onclick = () => { abierto = !abierto; document.querySelectorAll(".cve").forEach(d => d.open = abierto);
  $("toggle").textContent = abierto ? "Contraer todo" : "Expandir todo"; };

// ---------------------------------------------------------------- análisis (equivalente a la parte Python)
const enTexto = cve => ((cve.descriptions || []).find(d => d.lang === "en") || {}).value || "";
const cpes = cve => (cve.configurations || []).flatMap(c => (c.nodes || []).flatMap(n => (n.cpeMatch || []).map(m => m)));

function fabricanteDe(cve){
  const texto = enTexto(cve).toLowerCase();
  const vendors = new Set(cpes(cve).map(m => (m.criteria || "").toLowerCase().split(":")[3]).filter(Boolean));
  for (const f of Object.values(CONFIG.fabricantes))
    if (f.cpe.some(v => vendors.has(v)) || f.texto.some(t => texto.includes(t))) return f.nombre;
  return null;
}

function metrica(cve){
  const m = cve.metrics || {};
  for (const k of ["cvssMetricV40","cvssMetricV31","cvssMetricV30","cvssMetricV2"]) {
    if (m[k] && m[k].length) {
      const l = [...m[k]].sort((a,b) => (a.type !== "Primary") - (b.type !== "Primary"))[0];
      const d = l.cvssData;
      return {score: d.baseScore ?? null, sev: (d.baseSeverity || l.baseSeverity || "").toUpperCase(),
              ver: k.replace("cvssMetric",""), vector: d.vectorString || ""};
    }
  }
  return {score: null, sev: "SIN PUNTUAR", ver: "", vector: ""};
}

function requisitos(vector){
  const p = Object.fromEntries(vector.split("/").filter(x => x.includes(":") && !x.startsWith("CVSS")).map(x => x.split(":")));
  if (!Object.keys(p).length) return [[], ""];
  const filas = Object.entries(CONFIG.traduccion).filter(([k]) => k in p).map(([k,[et,vals]]) => [et, vals[p[k]] || p[k]]);
  const donde = {N:"remotamente",A:"desde la red adyacente",L:"con acceso local",P:"con acceso físico"}[p.AV] || "";
  const auth = p.PR || {N:"N",S:"L",M:"L"}[p.Au] || "";
  const quien = {N:"sin autenticación",L:"con una cuenta de usuario",H:"con credenciales de administrador"}[auth] || "";
  const ui = (p.UI || "N") === "N" ? (quien.startsWith("sin") ? "ni interacción del usuario" : "sin interacción del usuario")
                                   : "y requiere que un usuario realice alguna acción";
  let res = ["Explotable", donde, quien, ui].filter(Boolean).join(" ");
  if (p.AT === "P" || p.AC === "H") res += ", siempre que se den ciertas condiciones";
  return [filas, res + "."];
}

function versionesCNA(affected){
  const filas = [], vistos = new Set();
  for (const a of affected || []) {
    let producto = a.product || "";
    if (a.platforms && a.platforms.length && !(a.platforms.length === 1 && a.platforms[0] === "Default")) producto += ` (${a.platforms.join(", ")})`;
    for (const v of a.versions || []) {
      if (v.status !== "affected") continue;
      let ini = v.version || ""; if (["0","*","n/a","unspecified"].includes(ini)) ini = "";
      const arreglos = (v.changes || []).filter(c => c.status === "unaffected" && c.at).map(c => c.at);
      let afectadas, corregida;
      if (v.lessThan) { afectadas = ini ? `${ini} → anteriores a ${v.lessThan}` : `Anteriores a ${v.lessThan}`; corregida = arreglos.length ? arreglos.join(" / ") : v.lessThan; }
      else if (v.lessThanOrEqual) { afectadas = ini ? `${ini} → ${v.lessThanOrEqual} (incluida)` : `Hasta ${v.lessThanOrEqual} (incluida)`; corregida = arreglos.length ? arreglos.join(" / ") : `Posterior a ${v.lessThanOrEqual}`; }
      else { afectadas = ini || "Todas"; corregida = arreglos.length ? arreglos.join(" / ") : "Consultar aviso"; }
      const k = [producto, afectadas, corregida].join("|");
      if (!vistos.has(k)) { vistos.add(k); filas.push({producto, afectadas, corregida}); }
    }
  }
  return filas;
}

function versionesNVD(cve){
  const filas = [], vistos = new Set();
  for (const m of cpes(cve)) {
    if (m.vulnerable === false) continue;
    const p = (m.criteria || "").split(":"); if (p.length < 6) continue;
    const producto = p[4].replace(/_/g," ").replace(/\b\w/g, c => c.toUpperCase());
    const ini = m.versionStartIncluding || m.versionStartExcluding || "";
    let afectadas, corregida;
    if (m.versionEndExcluding) { afectadas = ini ? `${ini} → anteriores a ${m.versionEndExcluding}` : `Anteriores a ${m.versionEndExcluding}`; corregida = m.versionEndExcluding; }
    else if (m.versionEndIncluding) { afectadas = ini ? `${ini} → ${m.versionEndIncluding} (incluida)` : `Hasta ${m.versionEndIncluding} (incluida)`; corregida = `Posterior a ${m.versionEndIncluding}`; }
    else if (!["*","-"].includes(p[5])) { afectadas = p[5]; corregida = "Consultar aviso"; }
    else continue;
    const k = [producto, afectadas, corregida].join("|");
    if (!vistos.has(k)) { vistos.add(k); filas.push({producto, afectadas, corregida}); }
  }
  return filas;
}

const textos = l => (l || []).filter(x => (x.lang || "en").startsWith("en") && x.value).map(x => x.value.split(/\s+/).join(" "));

// ---------------------------------------------------------------- descarga en directo
const espera = ms => new Promise(r => setTimeout(r, ms));
const estadoTxt = t => { $("estado").textContent = t; };

async function getJSON(url, intentos = 3){
  for (let i = 0; ; i++) {
    try {
      const ctrl = new AbortController(), t = setTimeout(() => ctrl.abort(), 120000);
      const r = await fetch(url, {signal: ctrl.signal, cache: "no-store"});
      clearTimeout(t);
      if (!r.ok) throw new Error("HTTP " + r.status);
      return await r.json();
    } catch (e) {
      if (i >= intentos - 1) throw e;
      estadoTxt(`Reintentando (${e.message})…`);
      await espera(10000 * (i + 1));
    }
  }
}

async function descargarNVD(desde, hasta, tramo = ""){
  const iso = d => d.toISOString().replace(/\.\d+Z$/, ".000Z");
  const out = []; let start = 0, total = null;
  while (true) {
    const pag = Math.floor(start / 2000) + 1;
    estadoTxt(`Descargando NVD${tramo ? ` · ${tramo}` : ""}${total ? ` · página ${pag}/${Math.ceil(total/2000)}` : ""}…`);
    const u = `${CONFIG.nvd}?pubStartDate=${iso(desde)}&pubEndDate=${iso(hasta)}&resultsPerPage=2000&startIndex=${start}`;
    const d = await getJSON(u);
    const lote = d.vulnerabilities || [];
    out.push(...lote.map(v => v.cve));
    total = d.totalResults || 0; start += lote.length;
    if (!lote.length || start >= total) return out;
    estadoTxt(`NVD${tramo ? ` · ${tramo}` : ""}: ${start}/${total} CVEs · esperando límite de la API…`);
    await espera(6500);   // límite público de NVD sin clave: 5 peticiones / 30 s
  }
}

async function detalleCNA(ids){
  const cache = store.get("vp-cna") || {}, ahora = Date.now();
  const pend = ids.filter(id => !cache[id] || ahora - cache[id].t > 12 * 3600e3);
  let hechos = 0;
  const trabajador = async () => {
    while (pend.length) {
      const id = pend.shift();
      try {
        const d = await getJSON(CONFIG.cveorg + id, 2);
        const c = (d.containers || {}).cna || {};
        cache[id] = {t: ahora, affected: c.affected || [], configurations: c.configurations || [],
                     solutions: c.solutions || [], workarounds: c.workarounds || [],
                     references: (c.references || []).map(r => r.url).slice(0, 6)};
      } catch (e) { console.warn("CVE.org", id, e); }
      estadoTxt(`Detalle de fabricante: ${++hechos}/${ids.length}…`);
    }
  };
  if (pend.length) await Promise.all(Array.from({length: 6}, trabajador));
  // la caché del navegador solo guarda lo de los últimos 120 días aproximadamente
  for (const k of Object.keys(cache)) if (ahora - cache[k].t > 30 * 864e5) delete cache[k];
  store.set("vp-cna", cache);
  return cache;
}

function construir(cve, kev){
  const m = metrica(cve);
  const k = kev[cve.id];
  return {
    cve: cve.id, fabricante: fabricanteDe(cve), publicado: (cve.published || "").slice(0, 10),
    cvss: m.score, severidad: m.sev, version_cvss: m.ver, vector: m.vector,
    explotada_kev: k ? "SÍ" : "", kev_fecha_limite: k ? k.dueDate || "" : "",
    cwe: [...new Set((cve.weaknesses || []).flatMap(w => (w.description || []).map(d => d.value)).filter(v => v.startsWith("CWE-")))].sort().join(", "),
    descripcion: enTexto(cve), url: `https://nvd.nist.gov/vuln/detail/${cve.id}`,
    _nvd: {configurations: cve.configurations || [], references: (cve.references || []).map(r => r.url)},
  };
}

function enriquecer(r, c){
  [r.requisitos, r.resumen_explotacion] = requisitos(r.vector || "");
  if (!c && !r._nvd) return r;   // sin datos nuevos: se conserva lo que ya había
  const previas = r.versiones || [];
  r.versiones = versionesCNA(c && c.affected);
  if (!r.versiones.length && r._nvd) r.versiones = versionesNVD(r._nvd);
  if (!r.versiones.length) r.versiones = previas;
  const valido = n => !!n && !["n/a","na","unknown","unspecified","*","-"].includes(n.trim().toLowerCase());
  let prods = [...new Set(((c && c.affected) || []).map(a => a.product).filter(valido))];
  if (!prods.length && r._nvd) prods = [...new Set(cpes(r._nvd).map(m => (m.criteria || "").split(":")[4]).filter(Boolean)
                                           .map(p => p.replace(/_/g," ").replace(/\b\w/g, x => x.toUpperCase())))];
  r.producto = prods.join(", ") || r.producto || "Producto no especificado";
  r.versiones.forEach(v => { if (!valido(v.producto.split(" (")[0])) v.producto = r.producto; });
  r.condiciones = textos(c && c.configurations);
  r.solucion = [...textos(c && c.solutions), ...textos(c && c.workarounds).map(t => "Mitigación: " + t)];
  const refs = (c && c.references && c.references.length) ? c.references : ((r._nvd && r._nvd.references) || []);
  r.aviso = refs[0] || r.aviso || "";
  delete r._nvd;
  return r;
}

let actualizando = false;
function ocupado(si){
  actualizando = si;
  $("refresh").disabled = si;
  $("status").classList.toggle("busy", si);
}

// KEV: copia oficial de CISA en GitHub (la web de CISA no permite consultas desde el navegador)
async function cargarKEV(){
  estadoTxt("Descargando catálogo CISA KEV…");
  try { return {ok: true, map: Object.fromEntries(((await getJSON(CONFIG.kev, 2)).vulnerabilities || []).map(v => [v.cveID, v]))}; }
  catch (e) {
    console.warn("KEV", e);
    return {ok: false, map: Object.fromEntries(estado.data.filter(r => r.explotada_kev).map(r => [r.cve, {dueDate: r.kev_fecha_limite}]))};
  }
}

// EPSS (FIRST.org) para las CVEs indicadas, 100 por consulta
async function cargarEPSS(lista){
  for (let i = 0; i < lista.length; i += 100) {
    const lote = lista.slice(i, i + 100);
    try {
      const d = await getJSON(`${CONFIG.epss}?cve=${lote.map(r => r.cve).join(",")}&limit=100`, 1);
      const m = Object.fromEntries((d.data || []).map(x => [x.cve, x]));
      lote.forEach(r => { const x = m[r.cve]; if (x) { r.epss = +x.epss; r.epss_pct = +x.percentile; } });
    } catch (e) { console.warn("EPSS", e); return; }
  }
}

// De los CVEs brutos de NVD, se queda con los de los fabricantes vigilados
function procesar(brutos, kevMap){
  const out = [];
  for (const cve of brutos) {
    if (cve.vulnStatus === "Rejected") continue;
    const r = construir(cve, kevMap);
    if (!r.fabricante) continue;
    if (CONFIG.min_cvss && (r.cvss == null || r.cvss < CONFIG.min_cvss)) continue;
    if (CONFIG.solo_kev && !r.explotada_kev) continue;
    out.push(r);
  }
  return out;
}

// Trae lo publicado desde la última actualización (y, una vez al día, rehace los últimos días para recoger cambios)
async function actualizar(){
  if (actualizando) return;
  ocupado(true);
  const hasta = new Date();
  try {
    const kev = await cargarKEV();
    const completa = hasta - new Date(estado.completa) > 24 * 3600e3;
    let desdeNVD = completa ? new Date(hasta - CONFIG.dias * 864e5) : new Date(new Date(estado.hasta) - 6 * 3600e3);
    if (desdeNVD < new Date(estado.desde)) desdeNVD = new Date(estado.desde);
    const nuevos = procesar(await descargarNVD(desdeNVD, hasta), kev.map);

    const m = new Map(estado.data.map(r => [r.cve, r]));
    const antes = new Set(m.keys());
    nuevos.forEach(r => m.set(r.cve, Object.assign(m.get(r.cve) || {}, r)));
    const cna = await detalleCNA(nuevos.map(r => r.cve));
    nuevos.forEach(r => enriquecer(m.get(r.cve), cna[r.cve]));
    await cargarEPSS(nuevos.map(r => m.get(r.cve)));
    for (const r of m.values()) {
      const k = kev.map[r.cve];
      r.explotada_kev = k ? "SÍ" : ""; r.kev_fecha_limite = k ? k.dueDate || "" : "";
      r.nueva = !antes.has(r.cve);
    }

    estado = {desde: estado.desde, hasta: hasta.toISOString(), completa: completa ? hasta.toISOString() : estado.completa, data: [...m.values()]};
    guardar();
    render();
    const n = nuevos.filter(r => !antes.has(r.cve)).length;
    estadoTxt((n ? `${n} CVE${n>1?"s":""} nueva${n>1?"s":""}` : "Sin novedades") + (kev.ok ? "" : " · no se pudo consultar CISA KEV"));
  } catch (e) {
    console.error(e);
    estadoTxt(`Error al actualizar: ${e.message}. Se mantienen los datos anteriores.`);
  } finally {
    ocupado(false);
    asegurarRango();
  }
}

// Histórico publicado junto al HTML (archivo.js): rangos largos al instante, sin consultar NVD.
// Se carga como <script> y no con fetch() para que funcione también al abrir el HTML con doble clic.
const cargarScript = src => new Promise((ok, mal) => {
  const el = document.createElement("script");
  el.src = src; el.onload = ok; el.onerror = () => mal(new Error("no se encontró " + src));
  document.head.appendChild(el);
});
let archivoIntentado = false;
async function cargarArchivo(){
  if (archivoIntentado || !CONFIG.archivo) return;
  archivoIntentado = true;
  try {
    estadoTxt("Cargando histórico…");
    await cargarScript(`${CONFIG.archivo}?v=${encodeURIComponent(CONFIG.generado)}`);
    const a = window.__ARCHIVO__;
    if (!a || !Array.isArray(a.data)) throw new Error("histórico vacío");
    const m = new Map(a.data.map(r => [r.cve, r]));
    estado.data.forEach(r => m.set(r.cve, r));   // lo descargado en este navegador es más reciente
    estado = {...estado, desde: a.desde < estado.desde ? a.desde : estado.desde, data: [...m.values()]};
    estadoTxt("");
  } catch (e) {
    console.warn("No se pudo cargar el histórico; se usará NVD", e);
  }
}

// Panel «Por periodo»: si la fecha elegida es anterior a lo que hay, carga el histórico o descarga solo el tramo que falta
async function asegurarRango(){
  if (vista !== "periodo" || actualizando || desdeSel >= isoDia(estado.desde)) return;
  ocupado(true);
  try {
    await cargarArchivo();
    if (desdeSel >= isoDia(estado.desde)) { render(); return; }
    const kev = await cargarKEV();
    const ini = new Date(desdeSel + "T00:00:00Z"), fin = new Date(estado.desde);
    const corto = d => d.toLocaleDateString("es-ES",{day:"numeric",month:"short",year:"numeric"});
    const brutos = [];
    // NVD admite como máximo 120 días por consulta
    for (let a = ini; a < fin; ) {
      const b = new Date(Math.min(+a + 120 * 864e5, +fin));
      brutos.push(...await descargarNVD(a, b, `${corto(a)} – ${corto(b)}`));
      a = b;
      if (a < fin) await espera(6500);
    }
    const nuevos = procesar(brutos, kev.map);
    const cna = await detalleCNA(nuevos.map(r => r.cve));
    nuevos.forEach(r => { enriquecer(r, cna[r.cve]); r.nueva = false; });
    await cargarEPSS(nuevos);
    const m = new Map(estado.data.map(r => [r.cve, r]));
    nuevos.forEach(r => { if (!m.has(r.cve)) m.set(r.cve, r); });
    estado = {...estado, desde: ini.toISOString(), data: [...m.values()]};
    guardar();
    render();
    estadoTxt(`Periodo cargado: ${nuevos.length} CVE${nuevos.length === 1 ? "" : "s"} más desde el ${fecha(desdeSel)}`);
  } catch (e) {
    console.error(e);
    estadoTxt(`No se pudo cargar el periodo: ${e.message}. Vuelve a elegir la fecha para reintentarlo.`);
  } finally {
    ocupado(false);
  }
}

function ponerVista(v){
  vista = v;
  store.set("vp-vista", v);
  $("tab-rec").setAttribute("aria-selected", String(v === "recientes"));
  $("tab-per").setAttribute("aria-selected", String(v === "periodo"));
  $("range").hidden = v !== "periodo";
  render();
  asegurarRango();
}
function marcarPresets(){
  document.querySelectorAll("#presets button").forEach(b => b.classList.toggle("on", haceDias(+b.dataset.d) === desdeSel));
}
function elegirDesde(fechaISO){
  const min = haceDias(MAX_DIAS), max = isoDia(Date.now());
  desdeSel = fechaISO < min ? min : fechaISO > max ? max : fechaISO;
  store.set("vp-desde", desdeSel);
  $("desde").value = desdeSel;
  marcarPresets();
  if (vista !== "periodo") return ponerVista("periodo");
  render();
  asegurarRango();
}
$("tab-rec").textContent = `Últimos ${CONFIG.dias} días`;
$("tab-rec").onclick = () => ponerVista("recientes");
$("tab-per").onclick = () => ponerVista("periodo");
$("desde").min = haceDias(MAX_DIAS);
$("desde").max = isoDia(Date.now());
$("desde").value = desdeSel;
$("desde").onchange = e => { if (e.target.value) elegirDesde(e.target.value); };
document.querySelectorAll("#presets button").forEach(b => b.onclick = () => elegirDesde(haceDias(+b.dataset.d)));
marcarPresets();
$("tab-rec").setAttribute("aria-selected", String(vista === "recientes"));
$("tab-per").setAttribute("aria-selected", String(vista === "periodo"));
$("range").hidden = vista !== "periodo";

// ---------------------------------------------------------------- botón y actualización automática
$("refresh").onclick = actualizar;
let temporizador = null;
function programar(){
  clearInterval(temporizador);
  const min = Number($("auto").value);
  store.set("vp-auto", min);
  if (min) temporizador = setInterval(actualizar, min * 60e3);
}
$("auto").value = String(store.get("vp-auto") ?? 0);
if (![...$("auto").options].some(o => o.value === $("auto").value)) $("auto").value = "0";
$("auto").onchange = programar;
programar();

render();
// si los datos llevan más tiempo sin actualizarse que el intervalo elegido, actualiza al abrir
const auto = Number($("auto").value);
if (auto && Date.now() - new Date(estado.hasta) > auto * 60e3) actualizar(); else asegurarRango();
abrirDesdeEnlace();
</script>
</body></html>
"""


def guardar_html(res, ruta, dias, seleccion, min_cvss=0, solo_kev=False, historico=None, archivo=None):
    def js(obj):  # JSON seguro para incrustar en <script>
        return json.dumps(obj, ensure_ascii=False).replace("</", "<\\/")

    # Lo que necesita el HTML para actualizarse solo desde el navegador
    ahora = datetime.now(timezone.utc)
    config = {
        "dias": dias, "min_cvss": min_cvss, "solo_kev": solo_kev,
        "generado": ahora.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        # periodo cubierto por los datos incluidos en el HTML
        "cubre_desde": (ahora - timedelta(days=historico or dias)).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "fabricantes": {k: FABRICANTES[k] for k in seleccion},
        "traduccion": TRADUCCION,
        "nvd": NVD_URL, "cveorg": CVE_ORG_URL, "kev": KEV_URL_GITHUB, "epss": EPSS_URL,
    }
    if archivo:
        config["archivo"] = os.path.basename(archivo["ruta"])
        config["archivo_desde"] = archivo["desde"]
    doc = PLANTILLA_HTML.replace("__DATA__", js(res)).replace("__CONFIG__", js(config))
    with open(ruta, "w", encoding="utf-8") as f:
        f.write(doc)
    print(f"HTML guardado en {ruta}", file=sys.stderr)


# ----------------------------------------------------------------------------- archivo anual

FMT_ISO = "%Y-%m-%dT%H:%M:%S.000Z"


def actualizar_archivo(dias, hasta, recientes, desde_recientes, seleccion, kev, min_cvss, solo_kev, api_key,
                       ruta_estado, ruta_cna):
    """Mantiene un archivo con las CVEs de los fabricantes vigilados de los últimos `dias` días.

    NVD no permite buscar por fabricante, así que hay que descargar todos los CVEs y filtrar. Eso se hace
    una sola vez por tramo: el archivo se guarda y en cada ejecución solo se descarga el hueco que falte.
    `recientes` son las CVEs ya calculadas en esta ejecución (desde `desde_recientes` hasta `hasta`).
    """
    estado = None
    if ruta_estado and os.path.exists(ruta_estado):
        try:
            with open(ruta_estado, encoding="utf-8") as f:
                estado = json.load(f)
        except (OSError, ValueError):
            estado = None
    leer = lambda t: datetime.strptime(t, FMT_ISO).replace(tzinfo=timezone.utc)
    inicio = hasta - timedelta(days=dias)
    datos = {r["cve"]: r for r in (estado or {}).get("data", [])}
    for r in datos.values():
        r["fabricante"] = marca_actual(r)
    if estado:
        huecos = [(inicio, leer(estado["desde"])), (leer(estado["hasta"]), desde_recientes)]
    else:
        huecos = [(inicio, desde_recientes)]
    huecos = [(a, b) for a, b in huecos if b - a > timedelta(hours=1)]
    pausa = 0.7 if api_key else 6.5
    for a, fin in huecos:
        print(f"Archivo: descargando {a:%Y-%m-%d} → {fin:%Y-%m-%d} (solo hace falta una vez)…", file=sys.stderr)
        while a < fin:
            b = min(a + timedelta(days=120), fin)   # NVD admite 120 días por consulta
            brutos = descargar_nvd(a, b, api_key)
            nuevos = filtrar(brutos, seleccion, kev, min_cvss)
            if solo_kev:
                nuevos = [r for r in nuevos if r["explotada_kev"]]
            enriquecer(nuevos, {c["id"]: c for c in brutos}, ruta_cna)
            for r in nuevos:
                datos.setdefault(r["cve"], r)
            a = b
            time.sleep(pausa)
    for r in recientes:  # lo de esta ejecución manda: tiene las puntuaciones y versiones más actuales
        datos[r["cve"]] = r
    corte = inicio.strftime("%Y-%m-%d")
    lista = [r for r in datos.values() if r["publicado"] >= corte]
    for r in lista:  # el estado de explotación (KEV) cambia con el tiempo
        k = kev.get(r["cve"])
        r["explotada_kev"] = "SÍ" if k else ""
        r["kev_fecha_limite"] = k.get("dueDate", "") if k else ""
    nuevo = {"desde": inicio.strftime(FMT_ISO), "hasta": hasta.strftime(FMT_ISO), "data": lista}
    if ruta_estado:
        with open(ruta_estado, "w", encoding="utf-8") as f:
            json.dump(nuevo, f, ensure_ascii=False)
    return nuevo


# ----------------------------------------------------------------------------- main

def main():
    if hasattr(sys.stdout, "reconfigure"):  # consola de Windows (cp1252) -> UTF-8
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    p = argparse.ArgumentParser(description="Vulnerabilidades recientes en productos de seguridad perimetral")
    p.add_argument("--dias", type=int, default=7, help="días hacia atrás (máx. 120). Por defecto 7")
    p.add_argument("--min-cvss", type=float, default=0, help="CVSS mínimo (p.ej. 7 para High/Critical)")
    p.add_argument("--fabricantes", default="", help=f"lista separada por comas. Disponibles: {','.join(FABRICANTES)}")
    p.add_argument("--solo-kev", action="store_true", help="mostrar solo las explotadas activamente")
    p.add_argument("--csv", help="guardar resultado en CSV")
    p.add_argument("--html", help="guardar informe HTML")
    p.add_argument("--json", help="guardar resultado en JSON")
    p.add_argument("--sin-cache", action="store_true", help="ignorar la caché local y descargarlo todo de nuevo")
    p.add_argument("--historico", type=int, default=30,
                   help="días de historial que se incluyen en el HTML para el panel «Por periodo» (máx. 120). Por defecto 30")
    p.add_argument("--archivo", type=int, default=0, metavar="DIAS",
                   help="genera además archivo.js junto al HTML con los últimos DIAS días (p. ej. 365) para que el "
                        "panel «Por periodo» cargue rangos largos al instante. La primera vez tarda; luego es incremental")
    a = p.parse_args()

    if not 1 <= a.dias <= 120:
        p.error("--dias debe estar entre 1 y 120 (límite de la API de NVD)")
    if not 1 <= a.historico <= 120:
        p.error("--historico debe estar entre 1 y 120")
    seleccion = [x.strip().lower() for x in a.fabricantes.split(",") if x.strip()] or list(FABRICANTES)
    desconocidos = [x for x in seleccion if x not in FABRICANTES]
    if desconocidos:
        p.error(f"fabricantes desconocidos: {desconocidos}. Disponibles: {', '.join(FABRICANTES)}")

    hasta = datetime.now(timezone.utc)
    desde = hasta - timedelta(days=a.dias)
    api_key = os.environ.get("NVD_API_KEY")
    print(f"Consultando NVD ({desde:%Y-%m-%d} → {hasta:%Y-%m-%d}){' con API key' if api_key else ''}…", file=sys.stderr)

    kev = descargar_kev()
    ruta_cache = None if a.sin_cache else os.path.join(os.path.dirname(os.path.abspath(__file__)), ".cache_nvd.json")
    # El HTML lleva además el historial de los últimos --historico días para el panel «Por periodo»
    dias_html = max(a.dias, a.historico) if a.html else a.dias
    cves = obtener_cves(hasta - timedelta(days=dias_html), hasta, api_key, ruta_cache)
    todos = filtrar(cves, seleccion, kev, a.min_cvss)
    if a.solo_kev:
        todos = [r for r in todos if r["explotada_kev"]]
    carpeta = os.path.dirname(os.path.abspath(__file__))
    enriquecer(todos, {c["id"]: c for c in cves}, None if a.sin_cache else os.path.join(carpeta, ".cache_cna.json"))
    corte = desde.strftime("%Y-%m-%d")
    res = [r for r in todos if r["publicado"] >= corte]
    kev_nuevos = kev_recientes(kev, desde, seleccion)

    anadir_epss(todos)
    archivo = None
    if a.html and a.archivo > dias_html:
        ruta_cna = None if a.sin_cache else os.path.join(carpeta, ".cache_cna.json")
        ruta_estado = None if a.sin_cache else os.path.join(carpeta, ".cache_archivo.json")
        archivo = actualizar_archivo(a.archivo, hasta, todos, hasta - timedelta(days=dias_html), seleccion, kev,
                                     a.min_cvss, a.solo_kev, api_key, ruta_estado, ruta_cna)
        anadir_epss(archivo["data"])   # el EPSS cambia cada día: se refresca todo el histórico
        archivo["ruta"] = os.path.join(os.path.dirname(os.path.abspath(a.html)), "archivo.js")
        with open(archivo["ruta"], "w", encoding="utf-8") as f:
            f.write("window.__ARCHIVO__=")
            json.dump({k: archivo[k] for k in ("desde", "hasta", "data")}, f, ensure_ascii=False, separators=(",", ":"))
            f.write(";\n")
        print(f"Archivo guardado en {archivo['ruta']} ({len(archivo['data'])} CVEs desde {archivo['desde'][:10]})",
              file=sys.stderr)

    imprimir(res, kev_nuevos, a.dias)
    if a.csv:
        guardar_csv(res, a.csv)
    if a.html:
        guardar_html(todos, a.html, a.dias, seleccion, a.min_cvss, a.solo_kev, dias_html, archivo)
    if a.json:
        with open(a.json, "w", encoding="utf-8") as f:
            json.dump({"resultados": res, "kev_nuevos": kev_nuevos}, f, ensure_ascii=False, indent=2)
        print(f"JSON guardado en {a.json}", file=sys.stderr)


if __name__ == "__main__":
    main()
