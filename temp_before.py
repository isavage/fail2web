from flask import Flask, jsonify, request, send_from_directory, redirect, g, make_response
from flask_cors import CORS
import os
import subprocess
import logging
from functools import wraps
import jwt
from datetime import timedelta, datetime
import json
import configparser
from pathlib import Path
import re
import time

app = Flask(__name__, static_folder='../frontend', static_url_path='')
app.config['SECRET_KEY'] = os.getenv('FAIL2WEB_SECRET_KEY', 'your-secret-key-here')
app.config['JWT_SECRET_KEY'] = os.getenv('FAIL2WEB_SECRET_KEY', 'your-secret-key-here')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)
CORS(app)

def add_cors_headers(response):
    """Add CORS headers to response"""
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Authorization')
    return response

# Logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# Get environment variables
USERNAME = os.getenv('FAIL2WEB_USERNAME', 'admin')
PASSWORD = os.getenv('FAIL2WEB_PASSWORD', 'admin')
jail_d_path = '/data/jail.d'  # Path to jail.d directory in container

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization')

        # First check Authorization header
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
        # Then check cookies
        if not token:
            token = request.cookies.get('token')

        if not token:
            if request.path.endswith('.html'):
                return redirect('/login.html')
            return jsonify({'error': 'Token is missing'}), 401

        try:
            # Store the decoded token in g object for access in routes
            g.decoded_token = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
            return f(*args, **kwargs)
        except jwt.ExpiredSignatureError:
            # Clear both cookie and localStorage
            response = make_response(
                jsonify({'error': 'Token has expired'}), 401
            )
            response.delete_cookie('token')
            return response
        except jwt.InvalidTokenError:
            response = make_response(
                jsonify({'error': 'Invalid token'}), 401
            )
            response.delete_cookie('token')
            return response
    return decorated

def fail2ban_command(cmd):
    try:
        # Consistent socket path
        socket_path = '/var/run/fail2ban/fail2ban.sock'
        command = ['fail2ban-client', '--socket', socket_path] + cmd.split()
        logger.debug(f"Executing command: {' '.join(command)}")
        
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False  # Don't raise exception on non-zero exit
        )
        
        stdout = result.stdout.strip()
        stderr = result.stderr.strip()
        logger.debug(f"Command output: '{stdout}'")
        logger.debug(f"Command stderr: '{stderr}'")
        logger.debug(f"Command return code: {result.returncode}")
        
        if result.returncode != 0:
            logger.error(f"Command failed with return code {result.returncode}: {stderr}")
            return None
        
        if cmd == 'status':
            # Parse jail list from status output
            for line in stdout.split('\n'):
                if 'Jail list:' in line:
                    jails_str = line.split('Jail list:')[1].strip()
                    if jails_str:
                        return jails_str.split(', ')
                    return []
        return stdout

    except Exception as e:
        logger.error(f"Unexpected error in fail2ban_command: {str(e)}")
        return None

@app.route('/')
def root():
    return redirect('/login.html')

@app.route('/login.html')
def login_page():
    return send_from_directory(app.static_folder, 'login.html')

@app.route('/index.html')
@token_required
def index_page():
    token = request.args.get('token') or request.cookies.get('token')
    if not token:
        return redirect('/login.html')
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if username == USERNAME and password == PASSWORD:
        token = jwt.encode({
            'user': username,
            'exp': datetime.utcnow() + timedelta(minutes=5)  # Increased to 5 minutes
        }, app.config['JWT_SECRET_KEY'], algorithm='HS256')
        
        response = jsonify({
            'token': token,
            'message': 'Login successful'
        })
        
        # Set token in cookie
        response.set_cookie(
            'token',
            token,
            httponly=True,
            secure=False,  # Set to True if using HTTPS
            samesite='Lax',
            max_age=300  # 5 minutes in seconds
        )
        return response
    
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/jails')
@token_required
def get_jails():
    try:
        logger.info("Attempting to get jail status from fail2ban")
        jails = fail2ban_command('status')
        if jails is None:
            logger.error("fail2ban_command returned None - unable to communicate with fail2ban")
            return jsonify({'error': 'Failed to communicate with fail2ban. Check if fail2ban is running and socket is accessible.'}), 500
        logger.info(f"Successfully retrieved jails: {jails}")
        return jsonify({'jails': jails if isinstance(jails, list) else []})
    except Exception as e:
        logger.error(f"Error in get_jails: {str(e)}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/banned/<jail>')
@token_required
def get_banned(jail):
    response = fail2ban_command(f'status {jail}')
    if response is None:
        return jsonify({'error': f'Failed to get status for jail {jail}'}), 500
    return jsonify({'status': response})

@app.route('/api/unban', methods=['POST'])
@token_required
def unban_ip():
    data = request.json
    jail_name = data.get('jail')
    ip_address = data.get('ip')
    if not jail_name or not ip_address:
        return jsonify({'error': 'Missing jail name or IP address'}), 400
    
    # Correct syntax: set <jail> unbanip <ip>
    response = fail2ban_command(f'set {jail_name} unbanip {ip_address}')
    if response is None:
        return jsonify({'error': 'Failed to unban IP'}), 500
    return jsonify({'status': 'success', 'message': response})

@app.route('/api/verify-token')
@token_required
def verify_token():
    return jsonify({'valid': True})

@app.route('/api/ban', methods=['POST'])
@token_required
def ban_ip():
    data = request.json
    jail_name = data.get('jail')
    ip_address = data.get('ip')
    
    if not jail_name or not ip_address:
        return jsonify({'error': 'Missing jail name or IP address'}), 400
    
    # Validate IP or CIDR format
    def is_valid_ip_or_cidr(ip):
        ip_regex = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        cidr_regex = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/([0-2]?[0-9]|3[0-2])$'
        return re.match(ip_regex, ip) or re.match(cidr_regex, ip)
    
    if not is_valid_ip_or_cidr(ip_address):
        return jsonify({'error': 'Invalid IP or CIDR format'}), 400
    
    # Execute the ban command
    response = fail2ban_command(f'set {jail_name} banip {ip_address}')
    
    if response is None:
        logger.error(f"Failed to execute ban command for IP {ip_address} in jail {jail_name}")
        return jsonify({'error': f'Failed to ban IP {ip_address} in jail {jail_name}. Check server logs for details.'}), 500
    
    # Fail2ban returns a number (e.g., "1") on success, even if already banned
    response_str = response.strip()
    if response_str.isdigit() and int(response_str) > 0:
        if 'already banned' in response_str.lower():
            return jsonify({'status': 'warning', 'message': f'IP {ip_address} was already banned in {jail_name}'}), 200
        return jsonify({'status': 'success', 'message': f'IP {ip_address} banned successfully in {jail_name}'})
    else:
        logger.error(f"Unexpected Fail2ban response: '{response}'")
        return jsonify({'error': f'Failed to ban IP {ip_address}. Unexpected response: {response}'}), 500

@app.route('/api/jails/config', methods=['GET'])
@token_required
def get_jail_configs():
    """Get all jail configuration files"""
    try:
        jail_configs = []
        jail_path = Path(jail_d_path)
        
        if jail_path.exists():
            for jail_file in jail_path.glob('*.local'):
                config = configparser.ConfigParser(interpolation=None)
                config.read(jail_file)
                
                jail_info = {
                    'name': jail_file.stem,
                    'filename': jail_file.name,
                    'enabled': False,
                    'filter': '',
                    'logpath': '',
                    'maxretry': 3,
                    'findtime': 3600,
                    'bantime': 600,
                    'action': ''
                }
                
                for section_name in config.sections():
                    section = dict(config[section_name])
                    if section_name == 'DEFAULT':
                        jail_info.update({k.lower(): v for k, v in section.items()})
                    else:
                        jail_info.update({k.lower(): v for k, v in section.items()})
                        jail_info['enabled'] = section.get('enabled', 'false').lower() == 'true'
                
                jail_configs.append(jail_info)
        
        return jsonify({'jails': jail_configs})
    except Exception as e:
        logger.error(f"Error reading jail configs: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/jails/config', methods=['POST'])
@token_required
def create_jail_config():
    """Create or update a jail configuration"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['name', 'filter', 'logpath']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        jail_name = data['name']
        jail_filename = f"{jail_name}.local"
        jail_filepath = Path(jail_d_path) / jail_filename
        
        # Write config file
        write_config_file(jail_filepath, data)
        
        # Clean reload: stop fail2ban, reload, restart
        logger.info(f"Performing clean reload for jail {jail_name}")
        
        # Stop fail2ban completely
        stop_response = fail2ban_command('stop')
        if stop_response is None:
            logger.error("Failed to stop fail2ban")
        
        # Wait for stop to complete
        time.sleep(2)
