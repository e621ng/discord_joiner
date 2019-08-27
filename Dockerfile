FROM alpine:edge

RUN apk --update add \
	--no-cache \
	bash python3 uwsgi \
	uwsgi-python3 && \
	pip3 install --upgrade pip && \
	addgroup -S www-data && \
	adduser -S -g www-data www-data

COPY ./app /opt/app
WORKDIR /opt/app
VOLUME /opt/app/db

RUN pip3 install -r requirements.txt && chown -R www-data:www-data /opt/app

ENV FETCH_SECRET=9874982374982hyniheinarisentioen343ast OAUTH2_CLIENT_ID=***REMOVED*** OAUTH2_CLIENT_SECRET=***REMOVED*** BOT_TOKEN="Bot ***REMOVED***" URL_SECRET="***REMOVED***"

EXPOSE 8000

CMD ["uwsgi", "--ini", "/opt/app/uwsgi.ini"]
