FROM alpine:latest

RUN apk add --update \
    python python-dev py-pip \
    build-base libffi-dev openssl-dev \
    xmlsec \
  && rm -rf /var/cache/apk/*

ADD requirements.txt /tmp
RUN pip install -r /tmp/requirements.txt

EXPOSE 9000
CMD python manage.py migrate && python manage.py runserver 0.0.0.0:9000