FROM python:3.11-alpine3.18

WORKDIR /opt/app
COPY ./app/requirements.txt /opt/app/requirements.txt
RUN pip3 install --no-cache-dir -r requirements.txt
COPY ./app /opt/app

CMD ["uwsgi", "--ini", "/opt/app/uwsgi.ini"]
