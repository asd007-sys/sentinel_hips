-- Ajuste del umbral de DDoS para que dispare con la muestra del profesor.
-- 30 queries DNS por segundo desde una misma IP ya es claramente un ataque.
UPDATE configuracion_modulos SET valor = '30'
WHERE modulo = 'ddos' AND parametro = 'ddos_dns_threshold';
