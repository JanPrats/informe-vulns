"""
¿Qué clientes del inventario están afectados por una CVE, y es explotable sin condiciones?

El inventario solo contiene alias (CLI-001…), fabricante, producto y versión. Los nombres reales de los
clientes se sustituyen al final, al montar el correo, y nunca se imprimen.

Estados posibles para cada equipo afectado:
  explotable  -> versión afectada y la CVE no exige ninguna configuración especial
  revisar     -> versión afectada, pero solo es explotable con cierta configuración (se indica cuál)
  version     -> el producto coincide, pero no se puede determinar si su versión está afectada
"""
import base64
import gzip
import json
import re

# ----------------------------------------------------------------------------- versiones
# Misma lógica que «¿Me afecta?» de la web: «3.2.0 p7» = «3.2 Patch 7», «3.4.0» = «3.4», «14.1-73.37» = [14,1,73,37]
_RE_PARCHE = re.compile(r"^(.*?)(?:^|[\s._-])p(?:atch)?\s*\.?\s*(\d+)\b", re.I)


def numeros(t):
    t = str(t)
    m = _RE_PARCHE.match(t)
    if m and re.search(r"\d", m.group(1)):
        base, parche = [int(x) for x in re.findall(r"\d+", m.group(1))], [int(m.group(2))]
    else:
        base, parche = [int(x) for x in re.findall(r"\d+", t)], []
    while len(base) > 1 and base[-1] == 0:
        base.pop()
    return base + parche


def comparar(a, b):
    for i in range(max(len(a), len(b))):
        x = a[i] if i < len(a) else -1
        y = b[i] if i < len(b) else -1
        if x != y:
            return -1 if x < y else 1
    return 0


def rango(t):
    for patron, f in (
        (r"^(.+?)\s*→\s*anteriores a (.+)$", lambda m: {"ini": m[1], "fin": m[2], "incl": False}),
        (r"^anteriores a (.+)$", lambda m: {"fin": m[1], "incl": False}),
        (r"^(.+?)\s*→\s*(.+?) \(incluida\)$", lambda m: {"ini": m[1], "fin": m[2], "incl": True}),
        (r"^hasta (.+?) \(incluida\)$", lambda m: {"fin": m[1], "incl": True}),
    ):
        m = re.match(patron, t, re.I)
        if m:
            return f(m)
    if re.match(r"^todas$", t, re.I):
        return {"todas": True}
    return {"exacta": t}


def rama_de(t):
    return ".".join(re.findall(r"\d+", str(t))[:2])


def arreglo_rama(r, rama):
    for f in r.get("arreglos") or []:
        if re.match(r"\d", f["rama"]) and rama_de(f["rama"]) == rama:
            return f["corregida"]
    return None


# ----------------------------------------------------------------------------- productos
# Cómo se llama un producto en el inventario -> cómo aparece en las CVEs (NVD / fabricante)
EQUIVALENCIAS = {
    "fortigate": ["fortios"], "fortios": ["fortios"], "fortiproxy": ["fortiproxy"], "fortimail": ["fortimail"],
    "fortiweb": ["fortiweb"], "fortimanager": ["fortimanager"], "fortianalyzer": ["fortianalyzer"],
    "fortisase": ["fortisase"], "forticlient ems": ["forticlientems", "forticlient ems", "ems"],
    "fortiswitch": ["fortiswitch"], "fortiadc": ["fortiadc"], "fortisiem": ["fortisiem"],
    "asa": ["adaptive security appliance", "asa"], "ftd": ["firepower threat defense", "ftd"],
    "firepower": ["firepower"], "fmc": ["firepower management center", "secure firewall management center"],
    "ise": ["identity services engine", "ise"], "sd-wan": ["sd-wan", "vmanage"], "vmanage": ["sd-wan", "vmanage"],
    "meraki": ["meraki"], "anyconnect": ["anyconnect", "secure client"],
    "pa-": ["pan-os"], "pan-os": ["pan-os"], "globalprotect": ["globalprotect", "pan-os"],
    "prisma access": ["prisma access"], "panorama": ["panorama", "pan-os"],
    "netscaler": ["adc", "netscaler", "gateway"], "citrix adc": ["adc", "netscaler"], "citrix gateway": ["gateway"],
    "firebox": ["fireware"], "fireware": ["fireware"],
    "big-ip": ["big-ip"], "f5": ["big-ip"],
    "srx": ["junos"], "junos": ["junos"],
    "tz": ["sonicos"], "nsa": ["sonicos"], "sonicos": ["sonicos"], "sma": ["sma"],
    "quantum": ["quantum", "gaia"], "gaia": ["gaia"], "check point": ["quantum", "gaia"],
    "client connector": ["client connector"], "zscaler": ["zscaler", "client connector"],
    "netskope": ["netskope"], "cato": ["cato"], "warp": ["warp"], "cloudflared": ["cloudflared"],
    "xg": ["sophos firewall", "xg"], "sophos": ["sophos firewall", "sophos"],
    "usg flex": ["usg flex"], "zywall": ["zywall", "usg"], "atp": ["atp"],
}


def _norm(t):
    return re.sub(r"\s+", " ", str(t).lower()).strip()


def claves_producto(producto_inventario):
    p = _norm(producto_inventario)
    claves = {p}
    for k, v in EQUIVALENCIAS.items():
        if k in p:
            claves.update(v)
    return claves


def coincide_producto(producto_inventario, producto_cve):
    pc = _norm(producto_cve)
    if not pc:
        return False
    return any(c and (c in pc or pc in _norm(producto_inventario)) for c in claves_producto(producto_inventario))


def coincide_fabricante(fab_inventario, fab_cve):
    a, b = _norm(fab_inventario), _norm(fab_cve)
    return bool(a) and bool(b) and (a in b or b in a)


# ----------------------------------------------------------------------------- explotabilidad
_FRASE_CONDICION = re.compile(
    r"[^.]*\b(?:only|when|if|where|provided that|requires?|required)\b[^.]*\b(?:enabled|configured|configuration|"
    r"installed|in use|activated|exposed|running|set up|turned on)\b[^.]*\.", re.I)


def condiciones_explotacion(r):
    """Motivos por los que la CVE solo es explotable con cierta configuración (lista vacía = sin condiciones)."""
    motivos = []
    partes = dict(p.split(":", 1) for p in (r.get("vector") or "").split("/") if ":" in p and not p.startswith("CVSS"))
    for c in r.get("condiciones") or []:
        motivos.append(c)
    for frase in _FRASE_CONDICION.findall(r.get("descripcion") or "")[:2]:
        frase = " ".join(frase.split())
        if frase not in motivos:
            motivos.append(frase)
    if not motivos and partes.get("AT") == "P":
        motivos.append("El fabricante indica que requiere una configuración o despliegue concreto (CVSS AT:P).")
    if not motivos and partes.get("AC") == "H":
        motivos.append("Complejidad de ataque alta: requiere condiciones específicas (CVSS AC:H).")
    return motivos


# ----------------------------------------------------------------------------- comparación
def _version_afectada(r, filas, version):
    """True / False / None (no se puede determinar) y la versión a la que actualizar."""
    v = numeros(version)
    if not v:
        return None, None
    es_lista = all("exacta" in rango(f["afectadas"]) for f in filas)
    coinciden = []
    for f in filas:
        g = rango(f["afectadas"])
        if g.get("todas"):
            dentro = True
        elif "exacta" in g:
            dentro = comparar(v, numeros(g["exacta"])) == 0
        else:
            sobre = not g.get("ini") or comparar(v, numeros(g["ini"])) >= 0
            c = comparar(v, numeros(g["fin"]))
            dentro = sobre and (c <= 0 if g["incl"] else c < 0)
        if dentro:
            fin = numeros(g.get("fin") or g.get("exacta") or "")
            comun = 0
            while comun < len(v) and comun < len(fin) and v[comun] == fin[comun]:
                comun += 1
            coinciden.append((comun, f))
    del_aviso = arreglo_rama(r, rama_de(version))
    if coinciden:
        coinciden.sort(key=lambda x: -x[0])
        arreglo = del_aviso if del_aviso and re.match(r"\d", del_aviso) else coinciden[0][1]["corregida"]
        return True, arreglo
    if del_aviso and re.match(r"\d", del_aviso) and comparar(v, numeros(del_aviso)) >= 0:
        return False, None
    # con una lista de versiones sueltas no se puede afirmar «no afectada» si la rama aparece en la lista
    if es_lista and any(rama_de(f["afectadas"]) == rama_de(version) for f in filas):
        return None, None
    return False, None


def afectados(r, inventario):
    """Equipos del inventario afectados por la CVE r. Devuelve una lista de dicts (sin nombres de cliente)."""
    salida = []
    condiciones = condiciones_explotacion(r)
    for eq in inventario:
        if not coincide_fabricante(eq.get("fabricante", ""), r.get("fabricante", "")):
            continue
        filas = [f for f in r.get("versiones") or [] if coincide_producto(eq.get("producto", ""), f.get("producto", ""))]
        if not filas:
            # sin tabla de versiones de ese producto: solo se avisa si el producto aparece en la CVE
            texto = _norm(" ".join([r.get("producto", ""), r.get("descripcion", "")]))
            if not r.get("versiones") and any(c in texto for c in claves_producto(eq.get("producto", ""))):
                salida.append({**eq, "estado": "version", "arreglo": None, "condiciones": condiciones})
            continue
        afectado, arreglo = _version_afectada(r, filas, eq.get("version", ""))
        if afectado is None:
            salida.append({**eq, "estado": "version", "arreglo": None, "condiciones": condiciones})
        elif afectado:
            salida.append({**eq, "estado": "revisar" if condiciones else "explotable",
                           "arreglo": arreglo, "condiciones": condiciones})
    orden = {"explotable": 0, "revisar": 1, "version": 2}
    return sorted(salida, key=lambda x: (orden[x["estado"]], x["alias"]))


# ----------------------------------------------------------------------------- secretos
def empaquetar(obj):
    """JSON comprimido en base64 (para guardarlo como secreto de GitHub, máx. 48 KB)."""
    return base64.b64encode(gzip.compress(json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode())).decode()


def desempaquetar(texto):
    if not texto:
        return None
    return json.loads(gzip.decompress(base64.b64decode(texto)).decode())
