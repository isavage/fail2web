FROM alpine:3.17

WORKDIR /app

# Install Python, pip, and fail2ban-client
RUN apk add --no-cache python3 py3-pip fail2ban && \
    ln -sf python3 /usr/bin/python

# Install Flask dependencies
COPY src/backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/backend/ backend/
COPY src/frontend/ frontend/

EXPOSE 5000

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "backend.app:app"]