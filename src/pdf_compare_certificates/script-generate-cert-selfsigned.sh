# Nota: En la vida real, una FEC/QES requiere un certificado emitido 
# por una Autoridad de Certificación cualificada bajo eIDAS. 
# Aquí lo simulamos para fines educativos. 

# Generar clave privada y certificado FEA (normal)
openssl req -x509 -newkey rsa:2048 -keyout key_fea.pem -out cert_fea.pem -days 365 -nodes -subj "/CN=Universidad FEA"

# Generar clave privada y certificado FEC (simulado como cualificado)
openssl req -x509 -newkey rsa:2048 -keyout key_fec.pem -out cert_fec.pem -days 365 -nodes -subj "/CN=AC Raíz Cualificada eIDAS"