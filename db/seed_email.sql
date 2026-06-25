-- Configuracion del modulo de email (mailer)
-- La direccion del admin es a quien llegan las alertas.
INSERT INTO configuracion_modulos (modulo, parametro, valor) VALUES
('email', 'email_admin', 'asd@localhost'),
('email', 'email_remitente', 'hips@localhost');
