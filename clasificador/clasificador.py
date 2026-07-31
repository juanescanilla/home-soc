#!/usr/bin/env python3
import json
import time
import csv
import os
import requests
from datetime import datetime

# --- Configuración ---
ALERTS_FILE = "/var/ossec/logs/alerts/alerts.json"
CSV_FILE = "/home/vboxuser/clasificador-soc/incidentes.csv"

TELEGRAM_TOKEN = "TU_TOKEN_AQUI"
TELEGRAM_CHAT_ID = "TU_CHAT_ID_AQUI"

# Mapeo de tus reglas propias a categorías e info adicional
CATEGORIAS = {
    "100010": {"nombre": "Fuerza bruta SSH", "prioridad": "Alta"},
    "100011": {"nombre": "Gestión sospechosa de cuentas", "prioridad": "Media"},
}

# A partir de qué prioridad se envía a Telegram
ENVIAR_TELEGRAM = {"Alta", "Crítica"}


def clasificar(alerta):
    rule_id = str(alerta.get("rule", {}).get("id", ""))
    if rule_id in CATEGORIAS:
        return CATEGORIAS[rule_id]["nombre"], CATEGORIAS[rule_id]["prioridad"]
    # Si no es una de nuestras reglas propias, usamos el nivel de Wazuh como referencia
    nivel = alerta.get("rule", {}).get("level", 0)
    if nivel >= 12:
        return "Sin clasificar (nivel alto)", "Crítica"
    elif nivel >= 7:
        return "Sin clasificar (nivel medio)", "Media"
    else:
        return "Sin clasificar (nivel bajo)", "Baja"


def guardar_csv(fila):
    existe = os.path.isfile(CSV_FILE)
    with open(CSV_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        if not existe:
            writer.writerow(["fecha", "categoria", "prioridad", "nivel", "descripcion", "agente", "rule_id"])
        writer.writerow(fila)


def enviar_telegram(mensaje):
    try:
        requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
            data={"chat_id": TELEGRAM_CHAT_ID, "text": mensaje},
            timeout=5,
        )
    except Exception as e:
        print(f"Error enviando a Telegram: {e}")


def procesar_alerta(alerta):
    rule = alerta.get("rule", {})
    categoria, prioridad = clasificar(alerta)
    descripcion = rule.get("description", "Sin descripción")
    nivel = rule.get("level", 0)
    agente = alerta.get("agent", {}).get("name", "Desconocido")
    rule_id = rule.get("id", "N/A")
    fecha = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    guardar_csv([fecha, categoria, prioridad, nivel, descripcion, agente, rule_id])

    print(f"[{prioridad}] {categoria} - {descripcion} (agente: {agente})")

    if prioridad in ENVIAR_TELEGRAM:
        mensaje = (
            f"🚨 Incidente clasificado\n"
            f"Categoría: {categoria}\n"
            f"Prioridad: {prioridad}\n"
            f"Nivel Wazuh: {nivel}\n"
            f"Descripción: {descripcion}\n"
            f"Agente: {agente}"
        )
        enviar_telegram(mensaje)


def seguir_alertas():
    print("Clasificador de incidentes iniciado. Escuchando alertas...")
    with open(ALERTS_FILE, "r") as f:
        f.seek(0, os.SEEK_END)  # nos posicionamos al final, solo eventos nuevos
        while True:
            linea = f.readline()
            if not linea:
                time.sleep(1)
                continue
            try:
                alerta = json.loads(linea)
                procesar_alerta(alerta)
            except json.JSONDecodeError:
                continue


if __name__ == "__main__":
    seguir_alertas()
