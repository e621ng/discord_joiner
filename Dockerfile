FROM python:3.12-alpine3.19

WORKDIR /opt/app
COPY ./app/requirements.txt /opt/app/requirements.txt
RUN pip3 install --no-cache-dir -r requirements.txt
COPY ./app /opt/app

CMD ["uwsgi", "--ini", "/opt/app/uwsgi.ini"]
