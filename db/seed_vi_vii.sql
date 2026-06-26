-- Configuracion del modulo vi (procesos con alto consumo)
INSERT INTO configuracion_modulos (modulo, parametro, valor) VALUES
('procesos', 'umbral_consumo', '90'),
('procesos', 'check_interval', '10'),
('procesos', 'lecturas_sostenidas', '3');

-- Configuracion del modulo vii (/tmp)
INSERT INTO configuracion_modulos (modulo, parametro, valor) VALUES
('tmp', 'check_interval', '15');
