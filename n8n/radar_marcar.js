// Nodo «Marcar como avisados» del radar: solo se llega aquí si el correo se ha enviado bien.
// Si falla, no se marcan y se reintentan en la siguiente ejecución (también los cambios de los avisos vivos).
const cfg = $('Configuración').first().json;
if (!cfg.probar) {
  const estado = $getWorkflowStaticData('global');
  const leido = $('Leer boletines').first().json;
  const ahora = new Date();
  for (const id of leido.ids) estado.boletines[id] = ahora.toISOString();
  // se olvidan los avisados hace más de 30 días (los feeds solo traen lo de la última semana)
  const limite = new Date(ahora.getTime() - 30 * 864e5).toISOString();
  for (const [id, cuando] of Object.entries(estado.boletines)) if (cuando < limite) delete estado.boletines[id];
  // última lectura de cada aviso vivo, solo de los que se siguen recordando
  estado.huellas = Object.fromEntries(Object.entries(leido.huellas || {}).filter(([id]) => id in estado.boletines));
}
return [{ json: { enviado: true } }];
