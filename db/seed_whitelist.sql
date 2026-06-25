-- Lista blanca de IPs para el modulo x (accesos invalidos).
-- Estas IPs nunca se banean, para no bloquear al propio admin.
-- Separar varias IPs con comas. 127.0.0.1 siempre conviene incluirla.
INSERT INTO configuracion_modulos (modulo, parametro, valor) VALUES
('accesos', 'ip_whitelist', '127.0.0.1');
