FROM python:3.8-alpine

RUN apk add --update \
    build-base \
    cargo \
    gcc \
    musl-dev \
    libffi-dev \
    openssl-dev \
    xmlsec \
    xmlsec-dev \
  && rm -rf /var/cache/apk/*

ADD requirements.txt /tmp
RUN python3.8 -m pip install --no-cache-dir --upgrade \
    pip \
    setuptools \
    wheel
RUN pip install --no-cache-dir -r /tmp/requirements.txt

EXPOSE 9000
CMD python manage.py migrate && python manage.py runserver 0.0.0.0:9000
