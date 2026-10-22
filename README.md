# Informe de vulnerabilidades perimetrales

Listado de CVEs recientes en productos de seguridad perimetral (Palo Alto, Fortinet, Cisco, Check Point,
F5, Citrix, WatchGuard, Zscaler, etc.), agrupados por fabricante y producto, con
requisitos de explotación y versiones a las que actualizar.

Fuentes: NVD (NIST), CVE.org, CISA KEV y los feeds de boletines de los fabricantes.

## Publicación

GitHub Actions ejecuta `vulns_perimetrales.py` cada día a las 05:00 UTC y publica el resultado en GitHub Pages.
El HTML publicado además se puede actualizar en directo desde el navegador (botón «Actualizar»).

La página tiene dos vistas: **Últimos 7 días** y **Por periodo** (desde una fecha elegida hasta hoy, máximo 1 año).
El HTML incluye los últimos 30 días; para rangos más largos carga `archivo.js`, que GitHub Actions mantiene con
las CVEs del último año. La primera ejecución construye ese archivo (puede tardar 30-60 min); después es incremental.

- Lanzarlo a mano: pestaña **Actions** → *Generar y publicar informe* → **Run workflow**.
- Opcional: añade la clave gratuita del NVD como secreto `NVD_API_KEY`
  (Settings → Secrets and variables → Actions) para que la descarga sea más rápida y fiable.

## Avisos por correo

`avisos.py` se ejecuta cada 15 minutos (Actions → *Avisos por correo de CVEs nuevas*):

- Envía un correo cuando aparecen CVEs nuevas. Este correo no incluye clientes.
- Publica `novedades.json` en la rama `datos`.

El cruce con el inventario de clientes lo hace n8n dentro de Logicalis: en este repositorio no hay ningún dato
de clientes. Ver [n8n/LEEME.md](n8n/LEEME.md).

## Radar de boletines de los fabricantes

NVD no ve los avisos que salen sin CVE (*security hardening releases*, preavisos) ni el impacto de componentes de
terceros (PHP, OpenSSL…), cuyas CVEs constan como del componente. `boletines.py` lee los feeds RSS oficiales
listados en `boletines.json` y se queda con esos boletines:

- **Web:** franja ámbar «Avisos del fabricante» en la tarjeta de cada fabricante (últimos 30 días).
- **Correo de respaldo:** `avisos.py` envía un correo aparte cuando aparece uno nuevo y regenera la web.
- **Alerta rápida:** el flujo de n8n `radar_boletines.json` lee los mismos feeds cada 5 minutos.

Para añadir un feed o cambiar las reglas basta con editar `boletines.json`: lo leen GitHub y n8n.

```bash
python boletines.py --dias 30                                          # qué detecta ahora
python avisos.py --vista-previa correo.html --boletines                # correo de prueba, sin enviar
```

## Uso local

```bash
python vulns_perimetrales.py --dias 7 --html informe.html --csv informe.csv
```

Opciones: `--dias`, `--historico`, `--archivo`, `--min-cvss`, `--fabricantes`, `--solo-kev`, `--json`, `--sin-cache`.
