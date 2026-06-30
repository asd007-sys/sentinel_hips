-- Cuentas protegidas del modulo iv: nunca se bloquean.
-- Incluye la cuenta del admin (asd), root, el HIPS y postfix,
-- para que el modulo no bloquee al propio sistema o al admin.
INSERT INTO configuracion_modulos (modulo, parametro, valor) VALUES
('logs', 'cuentas_protegidas', 'asd,root,hips,postfix');
