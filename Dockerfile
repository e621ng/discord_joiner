FROM alpine:3.17

RUN apk --update add \
	--no-cache \
	bash python3 py3-pip uwsgi \
	uwsgi-python3 && \
	pip3 install --upgrade pip && \
#	addgroup -S www-data && \
	adduser -S -g www-data www-data

COPY ./app /opt/app
WORKDIR /opt/app
VOLUME /opt/app/db

RUN pip3 install -r requirements.txt && chown -R www-data:www-data /opt/app

EXPOSE 8000

CMD ["uwsgi", "--ini", "/opt/app/uwsgi.ini"]
