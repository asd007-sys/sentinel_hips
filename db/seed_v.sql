-- Configuracion del modulo v (cola de correo)
INSERT INTO configuracion_modulos (modulo, parametro, valor) VALUES
('correo', 'umbral_cola', '50'),
('correo', 'check_interval', '30');
