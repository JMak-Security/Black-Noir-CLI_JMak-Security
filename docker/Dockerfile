# Black Noir OSINT agent — isolated runtime.
# Running the sweep inside a disposable container keeps host separation; pair it
# with the optional gluetun VPN gateway in docker-compose.yml for IP isolation.
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY blacknoir ./blacknoir
COPY main.py ./
RUN mkdir -p input output

ENTRYPOINT ["python", "main.py"]
CMD ["--help"]
