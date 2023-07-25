FROM alpine:3.17

RUN apk --update add \
    --no-cache \
    bash python3 py3-pip uwsgi \
    uwsgi-python3 && \
    pip3 install --upgrade pip


WORKDIR /opt/app
COPY ./app/requirements.txt /opt/app/requirements.txt
RUN pip3 install -r requirements.txt
COPY ./app /opt/app

CMD ["uwsgi", "--ini", "/opt/app/uwsgi.ini"]
