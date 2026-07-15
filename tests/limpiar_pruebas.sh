#!/bin/bash
# ============================================================
# limpiar_pruebas.sh - sentinel_hips
# ------------------------------------------------------------
# Revierte los efectos que dejaron las pruebas de probar_todo.sh:
# borra reglas de iptables, el usuario de prueba, la tarea de cron,
# reinicia postfix si quedo apagado, etc.
#
# USO:  sudo bash tests/limpiar_pruebas.sh
# ============================================================

echo "============================================================"
echo " LIMPIEZA DE PRUEBAS - revirtiendo efectos"
echo "============================================================"
echo ""

# Borrar las reglas de iptables que pusieron los modulos
echo "Borrando reglas de iptables de las IPs de prueba..."
sudo iptables -D INPUT -s 203.0.113.77 -j DROP 2>/dev/null
sudo iptables -D INPUT -s 87.211.5.65 -j DROP 2>/dev/null
sudo iptables -D INPUT -s 89.40.233.100 2>/dev/null
sudo iptables -D INPUT -s 121.217.184.207 -j DROP 2>/dev/null
sudo iptables -D INPUT -s 198.51.100.23 -j DROP 2>/dev/null
echo "  (si alguna no existia, no pasa nada)"

# Borrar el usuario de prueba
echo "Borrando el usuario de prueba..."
sudo userdel -r usuario_intruso 2>/dev/null

# Regenerar el baseline de integridad (modulo i).
# Al borrar usuario_intruso, /etc/passwd y /etc/shadow volvieron a un
# estado limpio, pero el baseline guardado todavia tiene el hash viejo
# (con el usuario). Si no lo regeneramos, el modulo i disparara
# MODIFICACION_PASSWD/SHADOW apenas arranque el orquestador, aunque no
# haya ningun ataque. crear_baseline.py recalcula los hashes actuales.
echo "Regenerando el baseline de integridad (para que el modulo i no salte al arrancar)..."
# La raiz del proyecto es el directorio padre de tests/ (donde vive este script)
RAIZ="$(cd "$(dirname "$0")/.." && pwd)"
if [ -x "$RAIZ/venv/bin/python" ] && [ -f "$RAIZ/detection/crear_baseline.py" ]; then
  sudo "$RAIZ/venv/bin/python" "$RAIZ/detection/crear_baseline.py" >/dev/null 2>&1 \
    && echo "  Baseline regenerado." \
    || echo "  AVISO: no se pudo regenerar el baseline (revisar a mano)."
else
  echo "  AVISO: no encontre venv/bin/python o detection/crear_baseline.py."
  echo "         Regeneralo a mano: sudo venv/bin/python detection/crear_baseline.py"
fi

# Borrar la tarea de cron de prueba
echo "Borrando la tarea de cron de prueba..."
sudo rm -f /etc/cron.d/tarea_prueba

# Borrar el archivo de prueba de /tmp (si el modulo no lo borro)
echo "Borrando archivo de prueba de /tmp..."
sudo rm -f /tmp/malware_prueba.sh

# Restaurar Postfix a un estado sano. IMPORTANTE el orden:
#   1. LEVANTAR el servicio primero. El modulo iv, como prevencion,
#      apaga Postfix con systemctl stop cuando detecta correo masivo.
#      Si esta apagado, 'postsuper' no sirve (el correo esta caido).
#      Por eso se levanta ANTES.
#   2. Vaciar la cola: 'postsuper -d ALL' borra TODOS los mails,
#      incluidos los que el modulo v dejo en HOLD.
#   3. Por compatibilidad, si una corrida vieja dejo defer_transports
#      congelado (enfoque anterior), lo descongelamos.
echo "Restaurando Postfix (levantar + vaciar cola en hold)..."

# 1. Levantar Postfix por si el modulo iv lo bajo
sudo systemctl start postfix 2>/dev/null
sleep 2   # darle un momento a que el sistema de correo quede operativo

# 2. Vaciar la cola de prueba (incluye los mails en HOLD del modulo v)
sudo postsuper -d ALL 2>/dev/null

# 3. Compatibilidad con el enfoque viejo: descongelar si quedo residuo
if [ -f /var/log/hips/defer_transports.bak ]; then
  DEFER_PREVIO=$(cat /var/log/hips/defer_transports.bak)
  if [ -n "$DEFER_PREVIO" ]; then
    sudo postconf -e "defer_transports = $DEFER_PREVIO" 2>/dev/null
  else
    sudo postconf -X defer_transports 2>/dev/null
  fi
  sudo rm -f /var/log/hips/defer_transports.bak
  sudo systemctl reload postfix 2>/dev/null
else
  # Si quedo un defer_transports viejo sin backup, sacarlo igual
  ACTUAL=$(sudo postconf -h defer_transports 2>/dev/null)
  if [ -n "$ACTUAL" ]; then
    sudo postconf -X defer_transports 2>/dev/null
    sudo systemctl reload postfix 2>/dev/null
  fi
fi

# Confirmar que quedo escuchando en el puerto 25
if sudo ss -tlnp 2>/dev/null | grep -q ':25'; then
  echo "  Postfix operativo (escuchando en el puerto 25)."
else
  echo "  AVISO: Postfix no parece estar escuchando en el 25. Revisar con:"
  echo "         sudo systemctl status postfix"
fi

# Matar cualquier 'yes' que haya quedado corriendo
echo "Matando procesos 'yes' de prueba..."
sudo killall yes 2>/dev/null

# Vaciar el archivo de captura de DNS
echo "Vaciando el archivo de captura de DNS de prueba..."
sudo truncate -s 0 /var/log/hips/captura_dns.txt 2>/dev/null

echo ""
echo "============================================================"
echo " Limpieza terminada. El sistema quedo como antes de probar."
echo " (Las alarmas en la base y los logs se conservan como"
echo "  evidencia; si queres borrarlas tambien, se hace aparte.)"
echo "============================================================"
