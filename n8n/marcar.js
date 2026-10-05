// Nodo «Marcar como avisadas»: solo se llega aquí si el correo se ha enviado bien.
// Si falla, no se marcan y se reintentan en la siguiente ejecución.
const cfg = $('Configuración').first().json;
if (!cfg.probar) {
  const estado = $getWorkflowStaticData('global');
  const ahora = new Date();
  for (const id of $('Cruzar con clientes').first().json.ids) estado.avisadas[id] = ahora.toISOString();
  // se olvidan las avisadas hace más de 30 días (ya no pueden volver a aparecer en novedades.json)
  const limite = new Date(ahora.getTime() - 30 * 864e5).toISOString();
  for (const [id, cuando] of Object.entries(estado.avisadas)) if (cuando < limite) delete estado.avisadas[id];
}
return [{ json: { enviado: true } }];
