// Nodo «Configuración» del radar de boletines. Cambia estos valores y guarda el flujo.
return [{ json: {
  // Feeds y reglas (los mismos que usa GitHub). Se leen en cada ejecución: para añadir un feed basta con
  // cambiar boletines.json en el repositorio
  reglas_url: 'https://raw.githubusercontent.com/JanPrats/informe-vulns/main/boletines.json',

  // Enlace al informe web que se incluye en el correo
  informe_url: 'https://janprats.github.io/informe-vulns/',

  // Correo
  de: 'remitente@logicalis.com',          // el de la cuenta SMTP
  para: 'destinatario@logicalis.com',     // varios: separados por comas

  // Pruebas: true = envía ya un correo con los 3 boletines más recientes, sin marcar nada como avisado
  probar: false,
} }];
