FROM python:3.14-slim
WORKDIR /app

LABEL org.opencontainers.image.description="A Flask-based Certificate Authority (CA) demo application that provides certificate signing services."

# system deps for openssl usage
RUN apt-get update && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py ./
COPY ca_init.sh ./
RUN chmod +x ca_init.sh

EXPOSE 5000

# init CA and then start the app with gunicorn
CMD ["/bin/bash", "-lc", "./ca_init.sh && exec gunicorn -w 4 -b 0.0.0.0:5000 app:app"]
