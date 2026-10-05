# Avisos con clientes afectados (n8n)

GitHub **no tiene ningún dato de clientes**. Cada 15 minutos publica `novedades.json` con las CVEs de los
últimos 3 días: versiones afectadas, versiones corregidas, condiciones de explotación y el bloque del correo
ya montado. n8n, dentro de Logicalis, lo cruza con el Excel de clientes de SharePoint y envía el correo.

```
GitHub ── novedades.json (público, sin clientes) ──►  n8n  ◄── Excel de clientes (SharePoint)
                                                         └──► correo con los clientes afectados
```

GitHub sigue enviando su correo de respaldo, **sin clientes**, por si n8n falla.

## Flujo

| Nodo | Qué hace |
|---|---|
| Cada 10 minutos | Lanza el flujo |
| Configuración | Valores editables: Excel, correo, modo prueba (`configuracion.js`) |
| Descargar novedades | Descarga `novedades.json` de GitHub |
| CVEs sin avisar | Se queda con las que aún no se han avisado (`sin_avisar.js`) |
| Buscar sitio SharePoint / Descargar Excel | Descarga el Excel con Microsoft Graph |
| Leer Excel | Convierte la primera hoja en filas |
| Cruzar con clientes | Compara versiones, decide el estado de cada equipo y monta el correo (`cruce.js`) |
| Enviar correo | Por la cuenta SMTP de n8n |
| Marcar como avisadas | Solo si el correo ha salido bien (`marcar.js`) |

La primera ejecución activa no envía nada: solo marca como avisadas las CVEs que ya hay.

## Instalación

### 1. Permiso para leer el Excel (lo hace IT)

Registrar una aplicación en Entra ID:

- **Permiso:** Microsoft Graph → *Application* → `Sites.Selected`, con consentimiento de administrador.
- **Acceso:** solo **lectura** sobre el sitio de SharePoint donde está el Excel.
- **Datos que hay que entregar:** Tenant ID, Client ID y Client Secret.

### 2. Credencial en n8n

**Credentials → Add credential → OAuth2 API**:

| Campo | Valor |
|---|---|
| Grant Type | Client Credentials |
| Access Token URL | `https://login.microsoftonline.com/<TENANT_ID>/oauth2/v2.0/token` |
| Client ID / Client Secret | Los de la aplicación |
| Scope | `https://graph.microsoft.com/.default` |
| Authentication | Body |

### 3. Importar el flujo

1. **Workflows → Import from file** → `avisos_clientes.json`.
2. En **Buscar sitio SharePoint** y **Descargar Excel**, elegir la credencial OAuth2 del paso 2.
3. En **Enviar correo**, elegir la cuenta SMTP.
4. En **Configuración**, rellenar:
   - el sitio de SharePoint;
   - la ruta del Excel (relativa a la biblioteca «Documentos»);
   - el remitente y el destinatario.

### 4. Excel

Primera hoja, con esta cabecera en la primera fila:

| Cliente | Fabricante | Producto | Versión |
|---|---|---|---|
| Cliente A | Fortinet | FortiGate | 7.4.3 |
| Cliente A | Cisco | ASA | 9.18.4 |

Una fila por equipo. Los nombres de producto se traducen a los de las CVEs con la tabla `EQUIVALENCIAS` de
`afectacion.py` (p. ej. FortiGate → FortiOS, ASA → Adaptive Security Appliance). Si un producto no se
reconoce, hay que añadirlo ahí.

### 5. Probar

En **Configuración**, poner `probar: true` y ejecutar el flujo a mano. Se envía un correo con las 3 CVEs más
recientes, sin marcar nada como avisado.

Para probar con CVEs concretas:

1. En GitHub: **Actions → Avisos por correo → Run workflow**, con *probar* activado y las CVEs separadas
   por comas. Esto publica `prueba.json`.
2. En n8n, en **Configuración**:
   - `feed_url: '.../datos/prueba.json'`
   - `probar: true`
   - las CVEs en `cves_prueba`

Cuando funcione, volver a `novedades.json` con `probar: false` y **activar** el flujo.

## Estados de cada equipo

- **Vulnerable y explotable**: versión afectada y la CVE no exige ninguna configuración especial.
- **Vulnerable por versión · revisar si es explotable**: versión afectada, pero solo es explotable con cierta
  configuración (se indica cuál).
- **Revisar versión**: el producto coincide, pero no se puede determinar si la versión está afectada.

## Cambiar el código

Los `.js` de esta carpeta son el código de los nodos. Si cambias alguno:

1. Ejecuta `python n8n/generar_workflow.py`.
2. Vuelve a importar el flujo, o pega el `.js` en su nodo.
