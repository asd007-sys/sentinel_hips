-- Usuarios protegidos del modulo x: nunca se les cambia la contrasena.
-- Protege al admin (asd), root y la cuenta del HIPS de un auto-ataque.
INSERT INTO configuracion_modulos (modulo, parametro, valor) VALUES
('accesos', 'usuarios_protegidos', 'asd,root,hips');
