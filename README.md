# fail2web - Complete Fail2ban Management Solution
fail2web is a comprehensive Docker-based solution that includes both the fail2ban intrusion prevention system and a modern web management interface. This all-in-one package provides complete fail2ban functionality with an elegant, user-friendly web application for managing jails, banned IPs, and configurations.

## 🎯 What's Included

### **1. Fail2ban Service**
- **Production-ready fail2ban**: Fully configured intrusion prevention system
- **Persistent storage**: Configuration and data persistence across restarts
- **Log monitoring**: Automatic monitoring of mounted log directories

### **2. Fail2web Management Interface**
- **Modern web dashboard**: Clean, intuitive interface for managing fail2ban
- **Real-time monitoring**: Live updates of jail status and banned IPs
- **Configuration management**: Full control over jail settings and filters
- **Ignore IP management**: Easy management of IPs that should never be banned

### **3. Complete Docker Stack**
- **Multi-container architecture**: Separate, optimized containers for each component
- **Easy deployment**: One-command setup with docker-compose
- **Volume management**: Persistent storage for configurations and data
- **Network isolation**: Secure communication between components

![Screenshot 2025-02-28 at 7 32 16 PM](https://github.com/user-attachments/assets/6255ac88-0c25-457d-bc65-475de9d892e2)

![Screenshot 2025-02-28 at 7 33 12 PM](https://github.com/user-attachments/assets/89d984bd-e343-4e31-89fe-39ef19f083ff)

## 🚀 Features

### **Core Fail2ban Management**
- **Real-time Jail Monitoring**: View all active fail2ban jails with live status updates
- **Banned IP Management**: List, search, and unban IPs from any jail
- **Manual IP Banning**: Ban specific IPs or subnets directly from the web interface
- **Auto-refresh**: Automatic updates every 30 seconds to show current status

### **Advanced Jail Configuration**
- **Create New Jails**: Full jail creation wizard with smart defaults
- **Custom Filters**: Support for custom fail2ban filters with regex validation
- **Parameter Configuration**: Set maxretry, findtime, bantime, and actions

### **Ignore IP Management**
- **IPv4 & IPv6 Support**: Full support for both address families
- **CIDR Notation**: Support for network ranges (e.g., 192.168.0.0/16)

### **Security & Authentication**
- **JWT Authentication**: Secure token-based authentication
- **Session Management**: Automatic token verification and renewal
- **Inactivity Timeout**: Automatic logout after 1 minute of inactivity

### **User Interface**
- **Responsive Design**: Works on desktop and mobile devices
- **Modern Dashboard**: Clean, intuitive interface with real-time updates
- **Search & Filter**: Quickly find banned IPs

## 🛠️ Architecture

### **Backend (Python/Flask)**
- **RESTful API**: JSON-based API for all operations
- **Fail2ban Integration**: Direct communication via fail2ban-client socket
- **Configuration Management**: Reads/writes fail2ban config files
- **Error Handling**: Comprehensive error handling with user-friendly messages

### **Frontend (Vanilla JavaScript)**
- **No Frameworks**: Pure JavaScript for lightweight performance
- **Real-time Updates**: Live updates without page reloads
- **Form Validation**: Client-side validation for better UX
- **Responsive Layout**: Adaptive design for different screen sizes

### **Docker Containerization**
- **Multi-container Setup**: Separate containers for web app and fail2ban
- **Volume Mounts**: Persistent configuration and log storage
- **Network Isolation**: Secure communication between containers
- **Easy Deployment**: One-command setup with docker-compose

## 📋 Setup Instructions

### **1. Clone the Repository**
```bash
git clone https://github.com/isavage/fail2web.git
cd fail2web
```

### **2. Configure Environment**
```bash
# Rename the example environment file
cp .env.example .env

# Edit .env with your credentials
nano .env
```

### **3. Environment Variables**
Create a `.env` file with the following variables:
```bash
FAIL2WEB_USERNAME=admin
FAIL2WEB_PASSWORD=your_secure_password
FAIL2WEB_SECRET_KEY=your_jwt_secret_key
TZ=America/New_York
```

### **4. Configure Log Paths**
Edit the `volumes` section in `docker-compose.yml` to add your log directories:

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

### **5. Start the Application**
```bash
# Build and start the containers
docker compose up -d

# View logs
docker compose logs -f

# Stop the application
docker compose down
```

### **6. Access the Application**
- **Web Interface**: `http://localhost:5000`
- **Default Credentials**: admin / (password from .env file)


## 🔧 Technical Details

### **API Endpoints**
- `GET /api/jails` - List all active jails
- `GET /api/banned/{jail}` - Get banned IPs for a jail
- `POST /api/ban` - Ban an IP in a jail
- `POST /api/unban` - Unban an IP from a jail
- `GET /api/jails/config` - List jail configurations
- `POST /api/jails/config` - Create/update jail configuration
- `GET /api/ignoreip` - Get ignore IP list
- `POST /api/ignoreip` - Update ignore IP list
- `GET /api/filters/{filter}` - Get filter configuration
- `POST /api/login` - User authentication

### **File Structure**
```
fail2web/
├── src/
│   ├── backend/
│   │   ├── app.py              # Flask backend API
│   │   └── requirements.txt    # Python dependencies
│   └── frontend/
│       ├── index.html          # Main application
│       ├── login.html          # Login page
│       ├── css/                # Stylesheets
│       └── js/                 # JavaScript files
├── fail2ban/                  # Fail2ban configuration
├── docker-compose.yml         # Docker orchestration
├── Dockerfile                 # Web app container
└── README.md                  # This file
```

### **Security Features**
- **JWT Tokens**: 24-hour expiration with automatic renewal
- **Input Validation**: Server-side validation for all inputs
- **IP Validation**: Comprehensive IP/CIDR format checking
- **Error Handling**: Graceful error recovery without exposing details
- **Logging**: Appropriate logging levels (WARNING+ in production)



### **Logs and Debugging**
```bash
# View all container logs
docker compose logs -f

# View specific container logs
docker compose logs fail2web
docker compose logs fail2ban

# Enter container for debugging
docker compose exec fail2web bash
docker compose exec fail2ban bash

# Check fail2ban status
docker compose exec fail2ban fail2ban-client status
```

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make your changes
4. Test thoroughly
5. Submit a pull request

### **Development Setup**
```bash
# Clone your fork
git clone https://github.com/your-username/fail2web.git
cd fail2web

# Set up development environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r src/backend/requirements.txt

# Run backend locally
cd src/backend
python app.py

# The frontend will be served at http://localhost:5000
```

## 📄 License

This project is open source and available under the MIT License.

## 🙏 Acknowledgments

- **fail2ban**: The underlying intrusion prevention software
- **Flask**: Python web framework for the backend API
- **Docker**: Containerization platform for easy deployment
- **Contributors**: Everyone who has helped improve fail2web

---

**Note**: This application is designed to work with fail2ban running in a separate container. It communicates with fail2ban via its socket interface and manages configuration files in the shared `/data` volume.
