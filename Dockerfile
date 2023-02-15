FROM alpine:3.17

RUN apk --update add \
	--no-cache \
	bash python3 py3-pip uwsgi \
	uwsgi-python3 && \
	pip3 install --upgrade pip

COPY ./app /opt/app
WORKDIR /opt/app

RUN pip3 install -r requirements.txt

CMD ["uwsgi", "--ini", "/opt/app/uwsgi.ini"]
