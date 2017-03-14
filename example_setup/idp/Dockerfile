FROM alpine:latest

RUN apk add --update \
    python \
    python-dev \
    py-pip \
    build-base \
    openssl openssl-dev \
    git \
    libffi libffi-dev libxml2 libxml2-dev libxslt-dev libxslt \
    swig \
    xmlsec \
  && rm -rf /var/cache/apk/*

ADD requirements.txt /tmp
RUN pip install -r /tmp/requirements.txt

EXPOSE 8000
CMD python manage.py migrate && python manage.py runserver 0.0.0.0:9000