# fail2web
fail2web is a lightweight docker container web application designed to interact with the fail2ban service running in a separate docker container. It provides a modern and elegant interface for managing jails and banned IPs through a user-friendly web application.

![Screenshot 2025-02-28 at 7 32 16 PM](https://github.com/user-attachments/assets/6255ac88-0c25-457d-bc65-475de9d892e2)

![Screenshot 2025-02-28 at 7 33 12 PM](https://github.com/user-attachments/assets/89d984bd-e343-4e31-89fe-39ef19f083ff)

## Setup Instructions

1. Clone the repository:
   
   git clone https://github.com/isavage/fail2web.git
   
   cd fail2web
   

2. Rename .env.example to .env 

    FAIL2WEB_USERNAME=admin
    FAIL2WEB_PASSWORD=password
    FAIL2WEB_SECRET_KEY=you_secret_key
    FAIL2BAN_CONTAINER_NAME=



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
