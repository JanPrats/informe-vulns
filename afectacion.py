"""
Datos que GitHub publica en novedades.json para que n8n cruce las CVEs con el inventario de clientes:
  - condiciones de explotación de cada CVE (p. ej. «solo si FortiToken está activado»)
  - equivalencias entre cómo se llama un producto en el inventario y cómo aparece en las CVEs

Aquí no hay nada de clientes: la comparación de versiones y el cruce se hacen en n8n (ver n8n/cruce.js).
"""
import re

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
