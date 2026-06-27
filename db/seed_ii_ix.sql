-- Configuracion del modulo ii (usuarios conectados)
INSERT INTO configuracion_modulos (modulo, parametro, valor) VALUES
('usuarios', 'ip_whitelist', 'local,127.0.0.1'),
('usuarios', 'hora_inicio', '8'),
('usuarios', 'hora_fin', '20'),
('usuarios', 'check_interval', '30');

-- Configuracion del modulo ix (cron sospechoso)
INSERT INTO configuracion_modulos (modulo, parametro, valor) VALUES
('cron', 'patrones_sospechosos', '/tmp,/dev/shm,wget,curl,nc ,netcat,base64'),
('cron', 'check_interval', '60');
