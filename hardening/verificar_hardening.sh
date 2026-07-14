#!/bin/bash
# ============================================================
# verificar_hardening.sh - sentinel_hips
# ------------------------------------------------------------
# Verifica los 17 controles de hardening (10 del SO + 7 de la BD).
# Corre todos los comandos de verificacion de una vez y muestra
# el estado de cada control.
#
# USO:  sudo bash hardening/verificar_hardening.sh
# ============================================================

echo "============================================================"
echo " VERIFICACION DE HARDENING - sentinel_hips"
echo "============================================================"
echo ""
echo "--- HARDENING DEL SISTEMA OPERATIVO (Rocky Linux) ---"
echo ""

echo "[1] SELinux (debe decir Enforcing):"
getenforce
echo ""

echo "[2] Firewalld (debe decir running):"
firewall-cmd --state
echo ""

echo "[3] SSH - root deshabilitado (debe decir PermitRootLogin no):"
grep "^PermitRootLogin" /etc/ssh/sshd_config
echo ""

echo "[4] SSH - puerto cambiado (debe decir Port 2222):"
grep "^Port" /etc/ssh/sshd_config
echo ""

echo "[5] SSH - banner configurado (debe apuntar a /etc/issue.net):"
grep "^Banner" /etc/ssh/sshd_config
echo ""

echo "[6] /tmp con noexec (debe aparecer noexec):"
mount | grep " /tmp "
echo ""

echo "[7] auditd activo (debe decir active):"
systemctl is-active auditd
echo ""

echo "[8] Banner de login (contenido de /etc/issue.net):"
cat /etc/issue.net
echo ""

echo "[9] sudo restringido al grupo wheel:"
grep "^%wheel" /etc/sudoers
echo ""

echo "[10] Politica de contrasenas (debe decir minlen = 14):"
grep "^minlen" /etc/security/pwquality.conf
echo ""

echo "--- HARDENING DE LA BASE DE DATOS (PostgreSQL CIS) ---"
echo ""

echo "[BD-1] Usuario aplicativo sin superusuario (rolsuper debe ser f):"
sudo -u postgres psql -c "SELECT rolname, rolsuper FROM pg_roles WHERE rolname='hips_app';"

echo "[BD-2] Cifrado de contrasenas scram-sha-256:"
sudo -u postgres psql -c "SHOW password_encryption;"

echo "[BD-3] listen_addresses restringido (debe ser localhost):"
sudo -u postgres psql -c "SHOW listen_addresses;"

echo "[BD-4] log_connections activo:"
sudo -u postgres psql -c "SHOW log_connections;"

echo "[BD-5] log_disconnections activo:"
sudo -u postgres psql -c "SHOW log_disconnections;"

echo "[BD-6] connection_limit del rol aplicativo:"
sudo -u postgres psql -c "SELECT rolname, rolconnlimit FROM pg_roles WHERE rolname='hips_app';"

echo "============================================================"
echo " Verificacion completa."
echo "============================================================"
