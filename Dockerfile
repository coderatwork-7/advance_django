FROM python:3.11

ENV PYTHONUNBUFFERED 1
WORKDIR /app

ADD . .
# TESTING IT
RUN pip3 install --no-cache-dir -r requirements.txt

EXPOSE 8080
