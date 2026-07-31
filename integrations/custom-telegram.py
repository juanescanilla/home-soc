#!/usr/bin/env python3
import sys, json, requests

TOKEN = "TU_TOKEN_AQUI"
CHAT_ID = "TU_CHAT_ID_AQUI"

alert_file = sys.argv[1]
with open(alert_file) as f:
    alert = json.load(f)

rule = alert.get("rule", {})
mensaje = (
    f"🚨 Alerta Wazuh\n"
    f"Nivel: {rule.get('level')}\n"
    f"Descripción: {rule.get('description')}\n"
    f"Agente: {alert.get('agent', {}).get('name')}\n"
)

requests.post(
    f"https://api.telegram.org/bot{TOKEN}/sendMessage",
    data={"chat_id": CHAT_ID, "text": mensaje}
)
