FROM alpine:3.21

WORKDIR /app

# Install Python, pip, and fail2ban-client
RUN apk add --no-cache python3 py3-pip fail2ban && \
    ln -sf python3 /usr/bin/python

# Install Flask dependencies (--break-system-packages: PEP 668 on Alpine 3.19+)
COPY src/backend/requirements.txt .
RUN pip install --no-cache-dir --break-system-packages -r requirements.txt

COPY src/backend/ backend/
COPY src/frontend/ frontend/

EXPOSE 5000

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "backend.app:app"]