#!/usr/bin/env python3
"""
Monta avisos_clientes.json (el flujo para importar en n8n) a partir de los .js de esta carpeta.
Si cambias algún .js, vuelve a ejecutarlo:  python n8n/generar_workflow.py
"""
import json
import os
import uuid

CARPETA = os.path.dirname(os.path.abspath(__file__))


def js(nombre):
    with open(os.path.join(CARPETA, nombre), encoding="utf-8") as f:
        return f.read()


def nodo(nombre, tipo, version, x, parametros, **extra):
    return {"id": str(uuid.uuid5(uuid.NAMESPACE_URL, "vulns-n8n/" + nombre)), "name": nombre, "type": tipo,
            "typeVersion": version, "position": [x, 300], "parameters": parametros, **extra}


def codigo(nombre, archivo, x):
    return nodo(nombre, "n8n-nodes-base.code", 2, x, {"jsCode": js(archivo)})


CFG = "$('Configuración').first().json"
GRAPH = {"authentication": "genericCredentialType", "genericAuthType": "oAuth2Api"}

nodos = [
    nodo("Cada 10 minutos", "n8n-nodes-base.scheduleTrigger", 1.2, 0,
         {"rule": {"interval": [{"field": "minutes", "minutesInterval": 10}]}}),
    codigo("Configuración", "configuracion.js", 220),
    nodo("Descargar novedades", "n8n-nodes-base.httpRequest", 4.2, 440,
         {"url": "={{ $json.feed_url }}",
          "options": {"response": {"response": {"responseFormat": "json"}}}}),
    codigo("CVEs sin avisar", "sin_avisar.js", 660),
    nodo("Buscar sitio SharePoint", "n8n-nodes-base.httpRequest", 4.2, 880,
         {"url": f"=https://graph.microsoft.com/v1.0/sites/{{{{ {CFG}.sharepoint_host }}}}:{{{{ {CFG}.sharepoint_sitio }}}}",
          **GRAPH, "options": {}}),
    nodo("Descargar Excel", "n8n-nodes-base.httpRequest", 4.2, 1100,
         {"url": f"=https://graph.microsoft.com/v1.0/sites/{{{{ $json.id }}}}/drive/root:/{{{{ encodeURI({CFG}.ruta_excel) }}}}:/content",
          **GRAPH, "options": {"response": {"response": {"responseFormat": "file"}}}}),
    nodo("Leer Excel", "n8n-nodes-base.extractFromFile", 1, 1320, {"operation": "xlsx", "options": {}}),
    codigo("Cruzar con clientes", "cruce.js", 1540),
    nodo("Enviar correo", "n8n-nodes-base.emailSend", 2.1, 1760,
         {"fromEmail": "={{ $json.de }}", "toEmail": "={{ $json.para }}", "subject": "={{ $json.asunto }}",
          "emailFormat": "html", "html": "={{ $json.html }}", "options": {}}),
    codigo("Marcar como avisadas", "marcar.js", 1980),
]

conexiones = {}
for a, b in zip(nodos, nodos[1:]):
    conexiones[a["name"]] = {"main": [[{"node": b["name"], "type": "main", "index": 0}]]}

flujo = {
    "name": "Avisos de vulnerabilidades · clientes afectados",
    "nodes": nodos,
    "connections": conexiones,
    "settings": {"executionOrder": "v1"},
    "pinData": {},
}

ruta = os.path.join(CARPETA, "avisos_clientes.json")
with open(ruta, "w", encoding="utf-8") as f:
    json.dump(flujo, f, ensure_ascii=False, indent=2)
print(f"Flujo guardado en {ruta}")
