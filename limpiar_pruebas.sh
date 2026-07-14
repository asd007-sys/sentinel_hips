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
echo "  (si alguna no existia, no pasa nada)"

# Borrar el usuario de prueba
echo "Borrando el usuario de prueba..."
sudo userdel -r usuario_intruso 2>/dev/null

# Borrar la tarea de cron de prueba
echo "Borrando la tarea de cron de prueba..."
sudo rm -f /etc/cron.d/tarea_prueba

# Borrar el archivo de prueba de /tmp (si el modulo no lo borro)
echo "Borrando archivo de prueba de /tmp..."
sudo rm -f /tmp/malware_prueba.sh

# Reiniciar postfix por si el modulo iv lo bajo
echo "Reiniciando postfix (por si quedo apagado)..."
sudo systemctl start postfix 2>/dev/null

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
