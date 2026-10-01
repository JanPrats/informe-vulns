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
    "cisco":       {"nombre": "Cisco (ASA/FTD/FMC/ISE)", "cpe": [],
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
    "citrix":      {"nombre": "Citrix / NetScaler", "cpe": ["citrix"],
                    "texto": ["netscaler", "citrix adc", "citrix gateway"]},
    "ivanti":      {"nombre": "Ivanti (Connect/Policy Secure)", "cpe": ["ivanti", "pulsesecure"],
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
    "otros_fw":    {"nombre": "Array / Hillstone / Sangfor", "cpe": ["arraynetworks", "hillstonenet", "sangfor"],
                    "texto": ["array networks", "hillstone", "sangfor"]},
    "opnsense":    {"nombre": "pfSense / OPNsense", "cpe": ["netgate", "opnsense", "pfsense"],
                    "texto": ["pfsense", "opnsense"]},
}


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


def obtener_cves(desde, hasta, api_key, ruta_cache):
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
    if cache and datetime.strptime(cache["desde"], fmt) <= desde:
        # 6 h de solape para recoger CVEs que NVD indexa con retraso
        inicio = datetime.strptime(cache["hasta"], fmt) - timedelta(hours=6)
        print(f"Caché encontrada; descargando solo lo publicado desde {inicio:%Y-%m-%d %H:%M} UTC…", file=sys.stderr)
        cves = {c["id"]: c for c in cache["cves"]}
        for c in descargar_nvd(max(inicio, desde), hasta, api_key):
            cves[c["id"]] = c
        desde_cache = datetime.strptime(cache["desde"], fmt)
    else:
        cves = {c["id"]: c for c in descargar_nvd(desde, hasta, api_key)}
        desde_cache = desde
    # Mantenemos como mucho 120 días en caché
    limite = max(desde_cache, hasta - timedelta(days=120))
    cves = {k: c for k, c in cves.items() if c["published"] >= limite.strftime("%Y-%m-%dT%H:%M:%S")}
    if ruta_cache:
        with open(ruta_cache, "w", encoding="utf-8") as f:
            json.dump({"v": VERSION_CACHE, "desde": limite.strftime(fmt), "hasta": hasta.strftime(fmt), "cves": list(cves.values())}, f)
    corte = desde.strftime("%Y-%m-%dT%H:%M:%S")
    return [c for c in cves.values() if c["published"] >= corte]


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


def enriquecer(res, cves_por_id, ruta_cache):
    cna = descargar_cna([r["cve"] for r in res], ruta_cache)
    for r in res:
        c = cna.get(r["cve"], {})
        cve = cves_por_id[r["cve"]]
        r["requisitos"], r["resumen_explotacion"] = requisitos(r["vector"])
        r["versiones"] = _lineas_versiones(c.get("affected")) or _versiones_nvd(cve)
        productos = list(dict.fromkeys(a.get("product", "") for a in c.get("affected", []) if a.get("product")))
        if not productos:
            productos = list(dict.fromkeys(p.split(":")[4].replace("_", " ").title()
                                           for p in cpes(cve) if p.count(":") > 4))
        r["producto"] = ", ".join(productos) or "General"
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
        w = csv.DictWriter(f, fieldnames=list(res[0].keys()) if res else ["cve"], delimiter=";")
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
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@500&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#fbfbfa; --fg:#18181b; --muted:#71717a; --faint:#a1a1aa; --line:#e7e7e4; --soft:#f3f3f1; --link:#2952cc;
  --crit:#7e22ce; --high:#dc2626; --med:#c2410c; --low:#15803d; --none:#71717a; --ok:#15803d; --kev:#dc2626;
}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){
  --bg:#111113; --fg:#ececee; --muted:#9d9da6; --faint:#6b6b73; --line:#26262b; --soft:#1a1a1e; --link:#8ab4ff;
  --crit:#c084fc; --high:#f87171; --med:#fb923c; --low:#4ade80; --none:#9d9da6; --ok:#4ade80; --kev:#f87171;
}}
:root[data-theme="dark"]{
  --bg:#111113; --fg:#ececee; --muted:#9d9da6; --faint:#6b6b73; --line:#26262b; --soft:#1a1a1e; --link:#8ab4ff;
  --crit:#c084fc; --high:#f87171; --med:#fb923c; --low:#4ade80; --none:#9d9da6; --ok:#4ade80; --kev:#f87171;
}
*{box-sizing:border-box}
html,body{margin:0}
body{background:var(--bg);color:var(--fg);font:15px/1.6 Inter,system-ui,-apple-system,"Segoe UI",sans-serif;-webkit-font-smoothing:antialiased}
.mono,code{font-family:"JetBrains Mono",ui-monospace,Consolas,monospace;font-size:.92em}
a{color:var(--link);text-decoration:none} a:hover{text-decoration:underline}
.wrap{max-width:920px;margin:0 auto;padding:56px 16px 80px}

/* cabecera */
header h1{font-size:28px;font-weight:700;letter-spacing:-.02em;margin:0}
header .sub{color:var(--muted);margin:4px 0 0}
.index{display:flex;flex-wrap:wrap;gap:6px 20px;margin:24px 0 0;padding-top:20px;border-top:1px solid var(--line);font-size:14px}
.index a{color:var(--fg)} .index a span{color:var(--faint);margin-left:4px}

.controls{position:sticky;top:0;z-index:3;background:var(--bg);display:flex;flex-wrap:wrap;gap:10px 18px;align-items:center;padding:14px 0;margin-top:20px;border-bottom:1px solid var(--line)}
.controls input[type=search]{flex:1 1 240px;border:1px solid var(--line);background:transparent;color:var(--fg);border-radius:8px;padding:8px 12px;font:inherit;font-size:14px}
.controls input[type=search]:focus{outline:none;border-color:var(--fg)}
.controls label{font-size:14px;color:var(--muted);display:flex;gap:6px;align-items:center;cursor:pointer;user-select:none}
.controls button{background:none;border:0;color:var(--muted);font:inherit;font-size:14px;cursor:pointer;padding:0}
.controls button:hover{color:var(--fg)}
.theme{margin-left:auto}
.live{display:flex;gap:8px;align-items:center}
.controls .btn{border:1px solid var(--line);border-radius:8px;padding:6px 12px;color:var(--fg);background:var(--bg)}
.controls .btn:hover{border-color:var(--fg)}
.controls .btn:disabled{opacity:.5;cursor:wait}
.controls select{border:1px solid var(--line);border-radius:8px;padding:6px 8px;background:var(--bg);color:var(--fg);font:inherit;font-size:13px}
.estado{font-size:13px;color:var(--muted);margin:10px 0 0;min-height:20px}
.tag.new{color:var(--ok);border-color:var(--ok)}

/* fabricante y producto */
.vendor{margin-top:56px;scroll-margin-top:70px}
.vendor>h2{font-size:22px;font-weight:700;letter-spacing:-.01em;margin:0;display:flex;align-items:baseline;gap:12px;flex-wrap:wrap}
.vendor>h2 small{font-size:13px;font-weight:400;color:var(--muted)}
.product{margin-top:20px}
.product>h3{font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin:0 0 4px;padding-bottom:8px;border-bottom:1px solid var(--line)}

/* bloque CVE */
.cve{border-bottom:1px solid var(--line)}
.cve>summary{list-style:none;cursor:pointer;display:flex;align-items:center;gap:12px;padding:14px 0;flex-wrap:wrap}
.cve>summary::-webkit-details-marker{display:none}
.cve>summary::before{content:"";width:6px;height:6px;border-right:1.5px solid var(--faint);border-bottom:1.5px solid var(--faint);transform:rotate(-45deg);transition:transform .15s;margin:0 2px 0 0}
.cve[open]>summary::before{transform:rotate(45deg)}
.id{font-weight:500}
.sev{display:inline-flex;align-items:center;gap:6px;font-size:13px;color:var(--c);font-weight:600;font-variant-numeric:tabular-nums}
.sev::before{content:"";width:8px;height:8px;border-radius:50%;background:var(--c)}
.tag{font-size:11px;font-weight:600;letter-spacing:.04em;text-transform:uppercase;color:var(--kev);border:1px solid var(--kev);border-radius:4px;padding:0 6px}
.date{margin-left:auto;font-size:13px;color:var(--faint)}
.body{padding:0 0 22px 20px}
.row{display:grid;grid-template-columns:150px minmax(0,1fr);gap:16px;padding:12px 0;border-top:1px dashed var(--line)}
.row:first-child{border-top:0;padding-top:0}
.lbl{font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:var(--faint);padding-top:3px}
.desc{margin:0;color:var(--fg)}
.resumen{margin:0 0 10px;font-weight:600}
.reqs{display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:8px 18px;margin:0}
.reqs div{display:flex;flex-direction:column}
.reqs dt{font-size:12px;color:var(--muted)}
.reqs dd{margin:0;font-size:14px}
.reqs dd.peor{color:var(--high);font-weight:600}
.cond{margin:10px 0 0;font-size:14px;color:var(--muted)}
table{border-collapse:collapse;width:100%;font-size:14px}
th{font-size:12px;font-weight:500;color:var(--muted);text-align:left;padding:0 12px 6px 0;border-bottom:1px solid var(--line)}
td{padding:7px 12px 7px 0;border-bottom:1px solid var(--soft);vertical-align:top}
tr:last-child td{border-bottom:0}
td.fix{color:var(--ok);font-weight:600;white-space:nowrap}
.tblwrap{overflow-x:auto}
table.vtable{border:1px solid var(--line)}
.vtable th,.vtable td{border:1px solid var(--line);padding:8px 12px}
.vtable th{background:var(--soft);color:var(--fg);font-weight:600}
.vtable td.mono{white-space:nowrap}
.nota{margin:10px 0 0;font-size:13px;color:var(--muted)}
.links{display:flex;flex-wrap:wrap;gap:6px 18px;font-size:13px;color:var(--muted)}
.empty{color:var(--muted);padding:40px 0;text-align:center}

.s-CRITICAL{--c:var(--crit)} .s-HIGH{--c:var(--high)} .s-MEDIUM{--c:var(--med)} .s-LOW{--c:var(--low)} .s-NONE{--c:var(--none)}

footer{margin-top:72px;font-size:12px;color:var(--faint)}

@media (max-width:640px){.row{grid-template-columns:minmax(0,1fr);gap:4px}.body{padding-left:0}.date{margin-left:0;width:100%}}
@media print{.controls{display:none}.cve>summary::before{display:none}}
</style></head>
<body><div class="wrap">
<header>
  <h1>Informe Vulnerabilidades</h1>
  <p class="sub" id="periodo"></p>
  <nav class="index" id="index"></nav>
</header>
<div class="controls">
  <input type="search" id="q" placeholder="Buscar CVE, producto, versión…">
  <label><input type="checkbox" id="kev"> Solo explotadas</label>
  <button id="toggle">Expandir todo</button>
  <span class="live">
    <button id="refresh" class="btn">↻ Actualizar</button>
    <select id="auto" title="Actualización automática">
      <option value="0">Auto: no</option><option value="15">Cada 15 min</option><option value="30">Cada 30 min</option>
      <option value="60">Cada hora</option><option value="120">Cada 2 h</option><option value="360">Cada 6 h</option>
    </select>
  </span>
  <button class="theme" id="theme">Tema</button>
</div>
<p class="estado" id="estado"></p>
<main id="main"></main>
<footer>Fuentes: NVD (NIST), CVE.org (datos del fabricante) y CISA KEV. Confirma siempre las versiones en el aviso oficial del fabricante antes de actualizar.</footer>
</div>
<script>
// Datos generados por vulns_perimetrales.py (instantánea inicial) y configuración para actualizar en directo
let DATA = __DATA__;
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
  set(k,v){ try { localStorage.setItem(k, JSON.stringify(v)); } catch(e) {} },
};
const CLAVE = "vp-estado-" + CONFIG.dias + "-" + Object.keys(CONFIG.fabricantes).sort().join(",");

// Estado: la instantánea del HTML o, si es más reciente, la última actualización hecha en este navegador
let estado = {hasta: CONFIG.generado, completa: CONFIG.generado, data: DATA};
const guardado = store.get(CLAVE);
if (guardado && guardado.hasta > estado.hasta) { estado = guardado; DATA = guardado.data; }

// tema
const root = document.documentElement;
try { const t = localStorage.getItem("vp-theme"); if (t) root.dataset.theme = t; } catch(e) {}
$("theme").onclick = () => {
  const dark = root.dataset.theme ? root.dataset.theme === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
  root.dataset.theme = dark ? "light" : "dark";
  try { localStorage.setItem("vp-theme", root.dataset.theme); } catch(e) {}
};

// ---------------------------------------------------------------- pintado
function bloque(r){
  const s = sk(r.severidad);
  const reqs = r.requisitos.length
    ? `<p class="resumen">${esc(r.resumen_explotacion)}</p><dl class="reqs">${r.requisitos.map(([k,v]) =>
        `<div><dt>${esc(k)}</dt><dd class="${PEOR.includes(v)?"peor":""}">${esc(v)}</dd></div>`).join("")}</dl>`
    : `<p class="nota">El fabricante aún no ha publicado la métrica CVSS.</p>`;
  const cond = r.condiciones.length ? `<p class="cond"><b>Condiciones:</b> ${esc(r.condiciones.join(" "))}</p>` : "";
  const vers = r.versiones.length
    ? `<div class="tblwrap"><table class="vtable"><thead><tr><th>Producto</th><th>Versiones afectadas</th><th>Actualizar a</th></tr></thead><tbody>${
        r.versiones.map(v => `<tr><td>${esc(v.producto)}</td><td class="mono">${esc(v.afectadas)}</td><td class="mono fix">${esc(v.corregida)}</td></tr>`).join("")
      }</tbody></table></div>`
    : `<p class="nota">Sin datos de versiones estructurados. Consulta el aviso del fabricante.</p>`;
  const sol = r.solucion.length ? `<p class="nota">${esc(r.solucion.join(" "))}</p>` : "";
  return `<details class="cve${r.nueva ? " nueva" : ""}" data-id="${esc(r.cve)}" data-kev="${r.explotada_kev?1:0}" data-q="${esc([r.cve,r.fabricante,r.producto,r.descripcion,r.cwe,r.versiones.map(v=>v.afectadas+" "+v.corregida).join(" ")].join(" ").toLowerCase())}">
    <summary>
      <code class="id">${esc(r.cve)}</code>
      <span class="sev s-${s}">${r.cvss != null ? Number(r.cvss).toFixed(1) : "—"} ${SEV[s] || "Sin puntuar"}</span>
      ${r.explotada_kev ? `<span class="tag">Explotada</span>` : ""}
      ${r.nueva ? `<span class="tag new">Nueva</span>` : ""}
      <span class="date">${fecha(r.publicado)}</span>
    </summary>
    <div class="body">
      <div class="row"><div class="lbl">Descripción</div><p class="desc">${esc(r.descripcion.trim())}</p></div>
      <div class="row"><div class="lbl">Explotación</div><div>${reqs}${cond}</div></div>
      <div class="row"><div class="lbl">Versiones</div><div>${vers}${sol}</div></div>
      <div class="row"><div class="lbl">Referencias</div><div class="links">
        <a href="${esc(r.url)}" target="_blank" rel="noopener">NVD ↗</a>
        ${r.aviso ? `<a href="${esc(r.aviso)}" target="_blank" rel="noopener">Aviso del fabricante ↗</a>` : ""}
        ${r.cwe ? `<span class="mono">${esc(r.cwe)}</span>` : ""}
        ${r.kev_fecha_limite ? `<span style="color:var(--kev)">Límite CISA: ${fecha(r.kev_fecha_limite)}</span>` : ""}
      </div></div>
    </div></details>`;
}

function render(){
  const abiertos = new Set([...document.querySelectorAll(".cve[open]")].map(d => d.dataset.id));
  const grupos = {};
  DATA.forEach(r => ((grupos[r.fabricante] ??= {})[r.producto] ??= []).push(r));
  const fabs = Object.keys(grupos).map(f => {
    const todos = Object.values(grupos[f]).flat();
    return {f, todos, max: Math.max(...todos.map(prio))};
  }).sort((a,b) => b.max - a.max || b.todos.length - a.todos.length);

  const desde = new Date(new Date(estado.hasta) - CONFIG.dias * 864e5);
  $("periodo").textContent = `Publicadas del ${desde.toLocaleDateString("es-ES")} al ${new Date(estado.hasta).toLocaleDateString("es-ES")} · actualizado ${fechaHora(estado.hasta)}`;
  $("index").innerHTML = fabs.map(x => `<a href="#${slug(x.f)}">${esc(x.f)}<span>${x.todos.length}</span></a>`).join("");
  $("main").innerHTML = fabs.length ? fabs.map(({f, todos}) => {
    const c = k => todos.filter(r => sk(r.severidad) === k).length;
    const resumen = [[c("CRITICAL"),"crítica"],[c("HIGH"),"alta"],[c("MEDIUM"),"media"],[todos.filter(r=>r.explotada_kev).length,"explotada"]]
      .filter(x => x[0]).map(([n, t]) => `${n} ${t}${n > 1 ? "s" : ""}`).join(" · ");
    const prods = Object.entries(grupos[f]).sort((a,b) => Math.max(...b[1].map(prio)) - Math.max(...a[1].map(prio)));
    return `<section class="vendor" id="${slug(f)}"><h2>${esc(f)} <small>${todos.length} CVE${todos.length>1?"s":""}${resumen ? " · " + resumen : ""}</small></h2>
      ${prods.map(([p, rows]) => `<div class="product"><h3>${esc(p)}</h3>${rows.sort((a,b)=>prio(b)-prio(a)).map(bloque).join("")}</div>`).join("")}
    </section>`;
  }).join("") : `<p class="empty">No hay vulnerabilidades en el periodo.</p>`;
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

async function descargarNVD(desde, hasta){
  const iso = d => d.toISOString().replace(/\.\d+Z$/, ".000Z");
  const out = []; let start = 0, total = null;
  while (true) {
    const pag = Math.floor(start / 2000) + 1;
    estadoTxt(`Descargando NVD${total ? ` · página ${pag}/${Math.ceil(total/2000)}` : ""}…`);
    const u = `${CONFIG.nvd}?pubStartDate=${iso(desde)}&pubEndDate=${iso(hasta)}&resultsPerPage=2000&startIndex=${start}`;
    const d = await getJSON(u);
    const lote = d.vulnerabilities || [];
    out.push(...lote.map(v => v.cve));
    total = d.totalResults || 0; start += lote.length;
    if (!lote.length || start >= total) return out;
    estadoTxt(`NVD: ${start}/${total} CVEs · esperando límite de la API…`);
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
  for (const k of Object.keys(cache)) if (ahora - cache[k].t > 120 * 864e5) delete cache[k];
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
  let prods = [...new Set(((c && c.affected) || []).map(a => a.product).filter(Boolean))];
  if (!prods.length && r._nvd) prods = [...new Set(cpes(r._nvd).map(m => (m.criteria || "").split(":")[4]).filter(Boolean)
                                           .map(p => p.replace(/_/g," ").replace(/\b\w/g, x => x.toUpperCase())))];
  r.producto = prods.join(", ") || r.producto || "General";
  r.condiciones = textos(c && c.configurations);
  r.solucion = [...textos(c && c.solutions), ...textos(c && c.workarounds).map(t => "Mitigación: " + t)];
  const refs = (c && c.references && c.references.length) ? c.references : ((r._nvd && r._nvd.references) || []);
  r.aviso = refs[0] || r.aviso || "";
  delete r._nvd;
  return r;
}

let actualizando = false;
async function actualizar(){
  if (actualizando) return;
  actualizando = true;
  $("refresh").disabled = true;
  const hasta = new Date();
  try {
    // KEV: copia oficial de CISA en GitHub (la web de CISA no permite consultas desde el navegador)
    estadoTxt("Descargando catálogo CISA KEV…");
    let kev = null;
    try { kev = Object.fromEntries(((await getJSON(CONFIG.kev, 2)).vulnerabilities || []).map(v => [v.cveID, v])); }
    catch (e) { console.warn("KEV", e); }

    // Incremental: si la última descarga completa tiene menos de 24 h, solo pedimos lo nuevo (con 6 h de solape)
    const desdePeriodo = new Date(hasta - CONFIG.dias * 864e5);
    const completa = hasta - new Date(estado.completa) > 24 * 3600e3;
    const desdeNVD = completa ? desdePeriodo : new Date(Math.max(desdePeriodo, new Date(estado.hasta) - 6 * 3600e3));
    const nuevos = await descargarNVD(desdeNVD, hasta);

    const previos = new Map((completa ? [] : DATA).map(r => [r.cve, r]));
    const kevMap = kev || Object.fromEntries(DATA.filter(r => r.explotada_kev).map(r => [r.cve, {dueDate: r.kev_fecha_limite}]));
    for (const cve of nuevos) {
      if (cve.vulnStatus === "Rejected") continue;
      const r = construir(cve, kevMap);
      if (!r.fabricante) continue;
      if (CONFIG.min_cvss && (r.cvss == null || r.cvss < CONFIG.min_cvss)) continue;
      previos.set(r.cve, Object.assign(previos.get(r.cve) || {}, r));
    }
    const corte = desdePeriodo.toISOString().slice(0, 10);
    let lista = [...previos.values()].filter(r => r.publicado >= corte);
    lista.forEach(r => { const k = kevMap[r.cve]; r.explotada_kev = k ? "SÍ" : ""; r.kev_fecha_limite = k ? k.dueDate || "" : ""; });
    if (CONFIG.solo_kev) lista = lista.filter(r => r.explotada_kev);

    const cna = await detalleCNA(lista.map(r => r.cve));
    const antes = new Set(DATA.map(r => r.cve));
    lista.forEach(r => { enriquecer(r, cna[r.cve]); r.nueva = !antes.has(r.cve); });

    DATA = lista;
    estado = {hasta: hasta.toISOString(), completa: completa ? hasta.toISOString() : estado.completa, data: DATA};
    store.set(CLAVE, estado);
    render();
    const n = lista.filter(r => !antes.has(r.cve)).length;
    estadoTxt(n ? `${n} CVE${n>1?"s":""} nueva${n>1?"s":""}` : "Sin novedades");
    if (!kev) estadoTxt($("estado").textContent + " · no se pudo consultar CISA KEV");
  } catch (e) {
    console.error(e);
    estadoTxt(`Error al actualizar: ${e.message}. Se mantienen los datos anteriores.`);
  } finally {
    actualizando = false;
    $("refresh").disabled = false;
  }
}

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
if (auto && Date.now() - new Date(estado.hasta) > auto * 60e3) actualizar();
</script>
</body></html>
"""


def guardar_html(res, ruta, dias, seleccion, min_cvss=0, solo_kev=False):
    def js(obj):  # JSON seguro para incrustar en <script>
        return json.dumps(obj, ensure_ascii=False).replace("</", "<\\/")

    # Lo que necesita el HTML para actualizarse solo desde el navegador
    config = {
        "dias": dias, "min_cvss": min_cvss, "solo_kev": solo_kev,
        "generado": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "fabricantes": {k: FABRICANTES[k] for k in seleccion},
        "traduccion": TRADUCCION,
        "nvd": NVD_URL, "cveorg": CVE_ORG_URL, "kev": KEV_URL_GITHUB,
    }
    doc = PLANTILLA_HTML.replace("__DATA__", js(res)).replace("__CONFIG__", js(config))
    with open(ruta, "w", encoding="utf-8") as f:
        f.write(doc)
    print(f"HTML guardado en {ruta}", file=sys.stderr)


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
    a = p.parse_args()

    if not 1 <= a.dias <= 120:
        p.error("--dias debe estar entre 1 y 120 (límite de la API de NVD)")
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
    cves = obtener_cves(desde, hasta, api_key, ruta_cache)
    res = filtrar(cves, seleccion, kev, a.min_cvss)
    if a.solo_kev:
        res = [r for r in res if r["explotada_kev"]]
    carpeta = os.path.dirname(os.path.abspath(__file__))
    enriquecer(res, {c["id"]: c for c in cves}, None if a.sin_cache else os.path.join(carpeta, ".cache_cna.json"))
    kev_nuevos = kev_recientes(kev, desde, seleccion)

    imprimir(res, kev_nuevos, a.dias)
    if a.csv:
        guardar_csv(res, a.csv)
    if a.html:
        guardar_html(res, a.html, a.dias, seleccion, a.min_cvss, a.solo_kev)
    if a.json:
        with open(a.json, "w", encoding="utf-8") as f:
            json.dump({"resultados": res, "kev_nuevos": kev_nuevos}, f, ensure_ascii=False, indent=2)
        print(f"JSON guardado en {a.json}", file=sys.stderr)


if __name__ == "__main__":
    main()
