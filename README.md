# fail2web
fail2web is a lightweight docker container web application designed to interact with the fail2ban service running in a separate docker container. It provides a modern and elegant interface for managing jails and banned IPs through a user-friendly web application.

![Screenshot 2025-02-28 at 7 32 16 PM](https://github.com/user-attachments/assets/6255ac88-0c25-457d-bc65-475de9d892e2)

![Screenshot 2025-02-28 at 7 33 12 PM](https://github.com/user-attachments/assets/89d984bd-e343-4e31-89fe-39ef19f083ff)

## Setup Instructions

1. Clone the repository:
   
   git clone https://github.com/isavage/fail2web.git
   
   cd fail2web
   

2. Rename .env.example to .env 

## Configuration

### Environment Variables
Create a `.env` file with the following variables:
```bash
FAIL2WEB_USERNAME=admin
FAIL2WEB_PASSWORD=your_secure_password
FAIL2WEB_SECRET_KEY=your_jwt_secret_key
TZ=America/New_York
```

### Adding Additional Log Paths

To monitor additional log directories beyond `/var/log`, edit the `volumes` section in `docker-compose.yml`:

```yaml
volumes:
  - ./fail2ban/data:/data
  - /var/log:/var/log:ro
  # Add additional log paths here as needed:
  # - /var/log/nginx:/var/log/nginx:ro
  # - /opt/app/logs:/var/log/app:ro
  # - /home/user/custom_logs:/var/log/custom:ro
  # - /var/lib/docker/containers:/var/log/docker:ro
  ${NGINX_LOGS_PATH:-../nginx/logs}:/logs/nginx:ro
```

**Common Log Sources:**
- **Nginx**: `/var/log/nginx:/var/log/nginx:ro`
- **Application Logs**: `/opt/app/logs:/var/log/app:ro`
- **Docker Logs**: `/var/lib/docker/containers:/var/log/docker:ro`
- **Custom Logs**: `/home/user/custom_logs:/var/log/custom:ro`

**Format**: `/host/path:/container/path:permissions`
- `host/path`: Path on your host machine
- `container/path`: Mount point inside fail2ban container
- `permissions`: `ro` (read-only) or `rw` (read-write)

After adding new log paths, restart fail2ban:
```bash
docker compose restart fail2ban
```

2. Build and run the Docker containers:
   
   docker compose up -d
   

3. Access the web application at `http://localhost:5000`.

## Usage

- The application allows you to view all jails and banned IPs managed by fail2ban.
- You can unban IPs from the web interface.
- You can ban IPs or subnets using the web interface

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.

## License
