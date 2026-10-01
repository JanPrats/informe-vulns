# Informe de vulnerabilidades perimetrales

Listado de CVEs recientes en productos de seguridad perimetral (Palo Alto, Fortinet, Cisco, Check Point,
SonicWall, Juniper, F5, Citrix, Ivanti, Sophos, WatchGuard, etc.), agrupados por fabricante y producto, con
requisitos de explotación y versiones a las que actualizar.

Fuentes: NVD (NIST), CVE.org y CISA KEV.

## Publicación

GitHub Actions ejecuta `vulns_perimetrales.py` cada día a las 05:00 UTC y publica el resultado en GitHub Pages.
El HTML publicado además se puede actualizar en directo desde el navegador (botón «Actualizar»).

La página tiene dos vistas: **Últimos 7 días** y **Por periodo** (desde una fecha elegida hasta hoy, máximo 1 año).
El HTML incluye los últimos 30 días; para rangos más largos carga `archivo.js`, que GitHub Actions mantiene con
las CVEs del último año. La primera ejecución construye ese archivo (puede tardar 30-60 min); después es incremental.

- Lanzarlo a mano: pestaña **Actions** → *Generar y publicar informe* → **Run workflow**.
- Opcional: añade la clave gratuita del NVD como secreto `NVD_API_KEY`
  (Settings → Secrets and variables → Actions) para que la descarga sea más rápida y fiable.

## Uso local

```bash
python vulns_perimetrales.py --dias 7 --html informe.html --csv informe.csv
```

Opciones: `--dias`, `--historico`, `--archivo`, `--min-cvss`, `--fabricantes`, `--solo-kev`, `--json`, `--sin-cache`.
