#!/bin/bash

# Execute to generate new certificates

rm private.key
rm public.cert
openssl req -nodes -new -x509 -days 3650 -keyout private.key -out public.cert -subj '/CN=idp.localhost.com, C=BR, ST=RS, L=Caxias do Sul, O=Teste'