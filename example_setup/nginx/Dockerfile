FROM nginx

COPY etc/nginx/conf.d/default.conf /etc/nginx/conf.d/
COPY etc/ssl/certs/nginx-selfsigned.crt /etc/ssl/certs/
COPY etc/ssl/certs/dhparam.pem /etc/ssl/certs/
COPY etc/ssl/private/nginx-selfsigned.key /etc/ssl/private/

