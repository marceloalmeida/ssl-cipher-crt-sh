FROM python:3.12-slim
WORKDIR /usr/local/app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
RUN apt-get update && apt-get install -y \
    sslscan \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY ./ /usr/local/app/

CMD ["./run.sh"]
