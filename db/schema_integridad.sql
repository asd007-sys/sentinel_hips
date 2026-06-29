-- ============================================================
-- Tabla para el baseline de integridad (modulo i)
-- ============================================================
-- Guarda el hash de referencia de cada archivo critico.
-- El modulo i compara el hash actual contra el guardado aca.
-- Esto cumple el requisito del enunciado de guardar los
-- archivos de comparacion en la base de datos.

CREATE TABLE baseline_integridad (
    id           SERIAL PRIMARY KEY,
    ruta_archivo VARCHAR(255) NOT NULL UNIQUE,
    hash_sha256  VARCHAR(64) NOT NULL,
    actualizado  TIMESTAMP NOT NULL DEFAULT now()
);
