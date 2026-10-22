// Nodo «Marcar como avisados» del radar: solo se llega aquí si el correo se ha enviado bien.
// Si falla, no se marcan y se reintentan en la siguiente ejecución.
const cfg = $('Configuración').first().json;
if (!cfg.probar) {
  const estado = $getWorkflowStaticData('global');
  const ahora = new Date();
  for (const id of $('Leer boletines').first().json.ids) estado.boletines[id] = ahora.toISOString();
  // se olvidan los avisados hace más de 30 días (los feeds solo traen lo de la última semana)
  const limite = new Date(ahora.getTime() - 30 * 864e5).toISOString();
  for (const [id, cuando] of Object.entries(estado.boletines)) if (cuando < limite) delete estado.boletines[id];
}
return [{ json: { enviado: true } }];
