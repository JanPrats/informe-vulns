// Nodo «Configuración». Cambia estos valores y guarda el flujo.
return [{ json: {
  // CVEs que publica GitHub cada 15 minutos (solo datos públicos de las CVEs, nada de clientes)
  feed_url: 'https://raw.githubusercontent.com/JanPrats/informe-vulns/datos/novedades.json',

  // Excel de clientes en SharePoint. Primera hoja, con la cabecera: Cliente | Fabricante | Producto | Versión
  sharepoint_host: 'logicalis.sharepoint.com',
  sharepoint_sitio: '/sites/NOMBRE-DEL-SITIO',
  ruta_excel: 'Carpeta/clientes.xlsx',   // ruta dentro de la biblioteca «Documentos» del sitio

  // Correo
  de: 'remitente@logicalis.com',          // el de la cuenta SMTP
  para: 'destinatario@logicalis.com',     // varios: separados por comas

  // true = solo enviar correo si alguna CVE nueva afecta a algún cliente
  solo_con_afectados: false,

  // Pruebas: true = envía ya un correo con las CVEs de cves_prueba (o las 3 más recientes),
  // sin marcar nada como avisado. Para probar con CVEs antiguas: feed_url = .../datos/prueba.json
  probar: false,
  cves_prueba: [],
} }];
