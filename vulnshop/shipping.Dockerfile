FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# A imagem do frete contém apenas o serviço interno, para que o Command
# Injection não alcance o código, o banco ou as demais flags da loja.
COPY shipping_service.py .
COPY scripts/frete.sh /app/scripts/frete.sh
RUN chmod +x /app/scripts/frete.sh

RUN useradd --create-home app && chown -R app:app /app
USER app

EXPOSE 8000

CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "1", "--threads", "2", "shipping_service:app"]
