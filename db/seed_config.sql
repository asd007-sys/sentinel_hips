-- ============================================================
-- sentinel_hips - Datos iniciales de configuracion
-- ============================================================
-- Carga los umbrales por defecto de cada modulo en
-- configuracion_modulos. Estos valores se pueden editar
-- despues desde la interfaz web.
-- ============================================================

-- Modulo iii - sniffers
INSERT INTO configuracion_modulos (modulo, parametro, valor) VALUES
('sniffer', 'sniffer_check_interval', '60'),
('sniffer', 'sniffer_authorized_interfaces', 'lo');

-- Modulo iv - analisis de logs
INSERT INTO configuracion_modulos (modulo, parametro, valor) VALUES
('logs', 'log_check_interval', '30'),
('logs', 'log_scan_404_threshold', '20');

-- Modulo viii - ddos (calibrado con el log del profesor)
INSERT INTO configuracion_modulos (modulo, parametro, valor) VALUES
('ddos', 'ddos_dns_window_seconds', '1'),
('ddos', 'ddos_dns_threshold', '50');

-- Modulo x - accesos invalidos
INSERT INTO configuracion_modulos (modulo, parametro, valor) VALUES
('accesos', 'max_failed_attempts', '5'),
('accesos', 'time_window_minutes', '10'),
('accesos', 'ban_duration_minutes', '30');
