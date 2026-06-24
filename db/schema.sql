-- ============================================================
-- sentinel_hips - Esquema de base de datos
-- Proyecto HIPS - Sistemas Operativos
-- ============================================================
-- Este script crea las 6 tablas del sistema.
-- Se ejecuta conectado a la base hips_db con el usuario hips_app.
-- ============================================================


-- ------------------------------------------------------------
-- Tabla: usuarios_web
-- Acceso a la interfaz web del HIPS.
-- ------------------------------------------------------------
CREATE TABLE usuarios_web (
    id            SERIAL PRIMARY KEY,
    username      VARCHAR(50) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    rol           VARCHAR(20) NOT NULL DEFAULT 'operador',
    ultimo_login  TIMESTAMP
);


-- ------------------------------------------------------------
-- Tabla: alarmas
-- Registro de todas las alarmas detectadas por los modulos.
-- ------------------------------------------------------------
CREATE TABLE alarmas (
    id          SERIAL PRIMARY KEY,
    timestamp   TIMESTAMP NOT NULL DEFAULT now(),
    tipo_alarma VARCHAR(50) NOT NULL,
    ip_origen   VARCHAR(45),
    modulo      VARCHAR(30) NOT NULL,
    resuelta    BOOLEAN NOT NULL DEFAULT false
);

CREATE INDEX idx_alarmas_timestamp ON alarmas (timestamp);
CREATE INDEX idx_alarmas_tipo ON alarmas (tipo_alarma);
CREATE INDEX idx_alarmas_ip ON alarmas (ip_origen);


-- ------------------------------------------------------------
-- Tabla: acciones_prevencion
-- Log de las acciones que toma el modulo de prevencion.
-- ------------------------------------------------------------
CREATE TABLE acciones_prevencion (
    id        SERIAL PRIMARY KEY,
    alarma_id INTEGER NOT NULL,
    accion    VARCHAR(100) NOT NULL,
    timestamp TIMESTAMP NOT NULL DEFAULT now(),
    resultado VARCHAR(20) NOT NULL,
    CONSTRAINT fk_acciones_alarma FOREIGN KEY (alarma_id) REFERENCES alarmas (id)
);

CREATE INDEX idx_acciones_alarma ON acciones_prevencion (alarma_id);


-- ------------------------------------------------------------
-- Tabla: configuracion_modulos
-- Umbrales y parametros editables de cada modulo.
-- ------------------------------------------------------------
CREATE TABLE configuracion_modulos (
    id        SERIAL PRIMARY KEY,
    modulo    VARCHAR(30) NOT NULL,
    parametro VARCHAR(50) NOT NULL,
    valor     VARCHAR(100) NOT NULL,
    activo    BOOLEAN NOT NULL DEFAULT true
);

CREATE INDEX idx_configuracion_modulo ON configuracion_modulos (modulo);


-- ------------------------------------------------------------
-- Tabla: historial_auditoria
-- Trazabilidad de cambios hechos desde el dashboard web.
-- ------------------------------------------------------------
CREATE TABLE historial_auditoria (
    id              SERIAL PRIMARY KEY,
    usuario_id      INTEGER NOT NULL,
    accion          VARCHAR(100) NOT NULL,
    tabla_afectada  VARCHAR(50),
    timestamp       TIMESTAMP NOT NULL DEFAULT now(),
    CONSTRAINT fk_auditoria_usuario FOREIGN KEY (usuario_id) REFERENCES usuarios_web (id)
);

CREATE INDEX idx_auditoria_usuario ON historial_auditoria (usuario_id);


-- ------------------------------------------------------------
-- Tabla: estadisticas_recursos
-- Metricas de CPU/RAM para el analisis de comportamiento anomalo.
-- ------------------------------------------------------------
CREATE TABLE estadisticas_recursos (
    id        SERIAL PRIMARY KEY,
    cpu_usage NUMERIC(5,2) NOT NULL,
    ram_usage NUMERIC(5,2) NOT NULL,
    timestamp TIMESTAMP NOT NULL DEFAULT now()
);

CREATE INDEX idx_estadisticas_timestamp ON estadisticas_recursos (timestamp);
