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
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        try:
            decoded = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
            if datetime.utcnow() > decoded['exp']:
                return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        except Exception:
            return jsonify({'error': 'Token validation failed'}), 401
        
        g.current_user = decoded['sub']
        return f(*args, **kwargs)

def fail2ban_command(cmd):
    try:
        # Use the correct socket path that fail2ban is actually using
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
            return None  # Indicate failure
        
        # Parse jail list from status command
        if cmd == 'status':
            lines = stdout.split('\n')
            for line in lines:
                if line.startswith('Number of jail:') or line.startswith('Status'):
                    continue
                if '-' in line:
                    parts = line.split('-')
                    if len(parts) >= 2:
                        jail_name = parts[1].strip()
                        if jail_name and jail_name not in ['-', 'Total', 'Number']:
                            return jail_name
            return [jail for jail in lines if jail and jail not in ['-', 'Total', 'Number']]
        
        return stdout
    except FileNotFoundError:
        logger.error(f"fail2ban-client command not found. Is fail2ban installed and in PATH? Command: {' '.join(command)}")
        return None
    except Exception as e:
        logger.error(f"Error executing fail2ban command: {e}")
        return None

@app.route('/')
def index():
    return send_from_directory('static')

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if username == USERNAME and password == PASSWORD:
            token = jwt.encode({
                'sub': username,
                'exp': datetime.utcnow() + app.config['JWT_ACCESS_TOKEN_EXPIRES']
            }, app.config['JWT_SECRET_KEY'])
            
            return jsonify({
                'token': token.decode(),
                'expires_in': '24 hours'
            })
        else:
            return jsonify({'error': 'Invalid credentials'}), 401
            
    except Exception as e:
        logger.error(f"Error in login: {str(e)}")
        return jsonify({'error': str(e)}), 500

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

@app.route('/api/jails/config')
@token_required
def get_jail_configs():
    try:
        jail_path = Path(jail_d_path)
        if not jail_path.exists():
            return jsonify({'error': 'Jail configuration directory not found'}), 404
        
        jail_configs = []
        
        # Read all .local files in jail.d directory
        for jail_file in jail_path.glob('*.local'):
            config = configparser.ConfigParser(interpolation=None)
            config.read(jail_file)
            
            jail_info = {
                'name': jail_file.stem,
                'enabled': '',
                'filter': '',
                'logpath': '',
                'maxretry': '',
                'findtime': '',
                'bantime': '',
                'action': ''
            }
            
            # Parse each section in the jail file
            for section_name in config.sections():
                section = dict(config[section_name])
                if section_name == 'DEFAULT':
                    jail_info.update(section)
                else:
                    jail_info.update(section)
            
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
                return add_cors_headers(jsonify({'error': f'Missing required field: {field}'})), 400
        
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
        
        # Start fail2ban (will auto-read new configs)
        start_response = fail2ban_command('start')
        if start_response is None:
            logger.error("Failed to start fail2ban")
        
        # Wait for startup and verify
        time.sleep(3)
        status_response = fail2ban_command('status')
        jail_active = jail_name in str(status_response) if status_response else False
        
        if not jail_active:
            logger.error(f"Jail {jail_name} failed to start. Checking jail status...")
            jail_status = fail2ban_command(f'status {jail_name}')
            logger.error(f"Individual jail status: {jail_status}")
            
            # Try alternative start method
            logger.info("Trying alternative start method...")
            alt_start_response = fail2ban_command(f'start {jail_name} --once')
            logger.info(f"Alternative start response: {alt_start_response}")
        
        return add_cors_headers(jsonify({
            'status': 'success',
            'message': f'Jail {jail_name} created and activated',
            'jail_active': jail_active,
            'stop_response': str(stop_response),
            'start_response': str(start_response),
            'status_response': str(status_response)
        }))
        
    except Exception as e:
        logger.error(f"Error creating jail config: {str(e)}")
        response = jsonify({'error': str(e)})
        response.status_code = 500
        return add_cors_headers(response)

def write_config_file(filepath, data):
    """Write configuration file with proper format"""
    jail_name = data['name']
    
    config = configparser.ConfigParser()
    config['DEFAULT']['include'] = '/data/jail.d/ignoreip.conf'
    
    config.add_section(jail_name)
    config.set(jail_name, 'enabled', str(data.get('enabled', True)).lower())
    config.set(jail_name, 'filter', data['filter'])
    config.set(jail_name, 'logpath', data['logpath'])
    config.set(jail_name, 'maxretry', str(data.get('maxretry', 3)))
    config.set(jail_name, 'findtime', str(data.get('findtime', 3600)))
    config.set(jail_name, 'bantime', str(data.get('bantime', 600)))
    
    if data.get('action'):
        config.set(jail_name, 'action', data['action'])
    
    # Ensure directory exists
    filepath.parent.mkdir(parents=True, exist_ok=True)
    
    with open(filepath, 'w') as f:
        config.write(f)

@app.route('/api/jails/config/<jail_name>', methods=['DELETE'])
@token_required
def delete_jail_config(jail_name):
    try:
        jail_filename = f"{jail_name}.local"
        jail_filepath = Path(jail_d_path) / jail_filename
        
        if not jail_filepath.exists():
            return jsonify({'error': f'Jail {jail_name} not found'}), 404
        
        # Stop the jail first
        fail2ban_command(f'stop {jail_name}')
        
        # Delete the configuration file
        jail_filepath.unlink()
        
        # Wait for filesystem sync before reload
        time.sleep(2)
        
        # Reload fail2ban to remove the jail cleanly
        reload_response = fail2ban_command('reload')
        
        return add_cors_headers(jsonify({
            'status': 'success',
            'message': f'Jail {jail_name} deleted successfully',
            'reload_successful': reload_response is not None,
            'reload_response': str(reload_response) if reload_response else "Failed"
        }))
        
    except Exception as e:
        logger.error(f"Error deleting jail config: {str(e)}")
        response = jsonify({'error': str(e)})
        response.status_code = 500
        return add_cors_headers(response)

@app.route('/api/jails/<jail_name>/start', methods=['POST'])
@token_required
def start_jail(jail_name):
    try:
        response = fail2ban_command(f'start {jail_name}')
        if response is None:
            return jsonify({'error': f'Failed to start jail {jail_name}'}), 500
        return jsonify({'status': 'success', 'message': response})
    except Exception as e:
        logger.error(f"Error starting jail: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/jails/<jail_name>/stop', methods=['POST'])
@token_required
def stop_jail(jail_name):
    try:
        response = fail2ban_command(f'stop {jail_name}')
        if response is None:
            return jsonify({'error': f'Failed to stop jail {jail_name}'}), 500
        return jsonify({'status': 'success', 'message': response})
    except Exception as e:
        logger.error(f"Error stopping jail: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/jails/reload', methods=['POST'])
@token_required
def reload_fail2ban():
    try:
        response = fail2ban_command('reload')
        if response is None:
            return jsonify({'error': 'Failed to reload fail2ban'}), 500
        return jsonify({'status': 'success', 'message': response})
    except Exception as e:
        logger.error(f"Error reloading fail2ban: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/jails/templates', methods=['GET'])
@token_required
def get_jail_templates():
    try:
        templates_path = '/data/jail-templates.conf'
        if not Path(templates_path).exists():
            return jsonify({'error': 'No templates available'}), 404
        
        templates = {}
        config = configparser.ConfigParser()
        config.read(templates_path)
        
        for section_name in config.sections():
            templates[section_name] = dict(config[section_name])
        
        return jsonify(templates)
        
    except Exception as e:
        logger.error(f"Error getting jail templates: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/jails/create-from-template', methods=['POST'])
@token_required
def create_jail_from_template():
    try:
        data = request.get_json()
        template_name = data.get('template')
        jail_name = data.get('jail_name')
        custom_params = data.get('custom_params', {})
        
        if not template_name or not jail_name:
            return jsonify({'error': 'Template name and jail name are required'}), 400
        
        templates_path = '/data/jail-templates.conf'
        if not Path(templates_path).exists():
            return jsonify({'error': 'No templates available'}), 404
        
        config = configparser.ConfigParser()
        config.read(templates_path)
        
        if template_name not in config:
            return jsonify({'error': f'Template {template_name} not found'}), 404
        
        jail_config = dict(config[template_name])
        jail_config.update(custom_params)
        
        jail_filename = f"{jail_name}.local"
        jail_filepath = Path(jail_d_path) / jail_filename
        
        jail_config_parser = configparser.ConfigParser()
        jail_config_parser['DEFAULT']['include'] = '/data/jail.d/ignoreip.conf'
        
        jail_config_parser.add_section(jail_name)
        
        for key, value in jail_config.items():
            jail_config_parser.set(jail_name, key, str(value))
        
        jail_filepath.parent.mkdir(parents=True, exist_ok=True)
        
        with open(jail_filepath, 'w') as f:
            jail_config_parser.write(f)
        
        reload_response = fail2ban_command('reload')
        
        return jsonify({
            'status': 'success',
            'message': f'Jail {jail_name} created from template',
            'reload_response': str(reload_response) if reload_response else "Failed"
        })
        
    except Exception as e:
        logger.error(f"Error creating jail from template: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/ignoreip', methods=['GET'])
@token_required
def get_ignoreip():
    try:
        ignoreip_file = Path(jail_d_path) / 'ignoreIP.conf'
        
        if not ignoreip_file.exists():
            return jsonify({'error': 'IgnoreIP configuration not found'}), 404
        
        config = configparser.ConfigParser(interpolation=None)
        config.read(ignoreip_file)
        
        ignoreip_list = []
        if config.has_option('DEFAULT', 'ignoreip'):
            ignoreip_str = config.get('DEFAULT', 'ignoreip')
            ignoreip_list = [ip.strip() for ip in ignoreip_str.split() if ip.strip()]
        
        return jsonify({'ignoreip': ignoreip_list})
        
    except Exception as e:
        logger.error(f"Error reading ignoreIP configuration: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/ignoreip', methods=['POST'])
@token_required
def update_ignoreip():
    try:
        data = request.get_json()
        ignoreip_list = data.get('ignoreip', [])
        
        if not isinstance(ignoreip_list, list):
            return jsonify({'error': 'ignoreip must be a list'}), 400
        
        ip_regex = r'^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        cidr_regex = r'^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/(3[0-2]|[12][0-9]|(3[0-1]?[0-9]?[0-9]?)$'
        
        for ip in ignoreip_list:
            if not ip.strip():
                continue
            if not (re.match(ip_regex, ip.strip()) or re.match(cidr_regex, ip.strip())):
                return jsonify({'error': f'Invalid IP/CIDR format: {ip}'}), 400
        
        config = configparser.ConfigParser()
        config.add_section('DEFAULT')
        ignoreip_text = '\n            '.join([ip.strip() for ip in ignoreip_list if ip.strip()])
        config.set('DEFAULT', 'ignoreip', ignoreip_text)
        
        ignoreip_file = Path(jail_d_path) / 'ignoreIP.conf'
        ignoreip_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(ignoreip_file, 'w') as f:
            config.write(f)
        
        reload_response = fail2ban_command('reload')
        
        return jsonify({
            'status': 'success',
            'message': 'IgnoreIP configuration updated successfully',
            'reload_response': str(reload_response) if reload_response else "Failed"
        })
        
    except Exception as e:
        logger.error(f"Error updating ignoreIP configuration: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/banned/<jail_name>')
@token_required
def get_banned(jail_name):
    response = fail2ban_command(f'status {jail_name}')
    if response is None:
        return jsonify({'error': f'Failed to get status for jail {jail_name}'}), 500
    return jsonify({'status': response})

@app.route('/api/ban', methods=['POST'])
@token_required
def ban_ip():
    try:
        data = request.get_json()
        jail_name = data.get('jail')
        ip_address = data.get('ip')
        
        if not jail_name or not ip_address:
            return jsonify({'error': 'Missing jail name or IP address'}), 400
        
        # Correct syntax: set <jail> banip <ip>
        response = fail2ban_command(f'set {jail_name} banip {ip_address}')
        if response is None:
            return jsonify({'error': f'Failed to ban IP {ip_address} in {jail_name}'}), 500
        
        # Fail2ban returns a number (e.g., "1") on success, even if already banned
        response_str = response.strip()
        if response_str.isdigit() and int(response_str) > 0:
            if 'already banned' in response_str.lower():
                return jsonify({'status': 'warning', 'message': f'IP {ip_address} was already banned in {jail_name}'}), 200
            return jsonify({'status': 'success', 'message': f'IP {ip_address} banned successfully in {jail_name}'})
        else:
            logger.error(f"Unexpected Fail2ban response: '{response_str}'")
            return jsonify({'error': f'Unexpected response from Fail2ban: {response_str}'}), 500
        
    except Exception as e:
        logger.error(f"Error banning IP: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/unban', methods=['POST'])
@token_required
def unban_ip():
    try:
        data = request.get_json()
        jail_name = data.get('jail')
        ip_address = data.get('ip')
        
        if not jail_name or not ip_address:
            return jsonify({'error': 'Missing jail name or IP address'}), 400
        
        # Correct syntax: set <jail> unbanip <ip>
        response = fail2ban_command(f'set {jail_name} unbanip {ip_address}')
        if response is None:
            return jsonify({'error': 'Failed to unban IP'}), 500
        return jsonify({'status': 'success', 'message': response})
    except Exception as e:
        logger.error(f"Error unbanning IP: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/verify-token')
@token_required
def verify_token():
    try:
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        try:
            decoded = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
            if datetime.utcnow() > decoded['exp']:
                return jsonify({'error': 'Token has expired'}), 401
            return jsonify({'valid': True, 'user': decoded['sub']})
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        except Exception:
            return jsonify({'error': 'Token validation failed'}), 401
    except Exception as e:
        logger.error(f"Error verifying token: {str(e)}")
        return jsonify({'error': str(e)}), 401


if __name__ == '__main__':
    # Check if we can connect to fail2ban socket
    try:
        subprocess.run(['fail2ban-client', '--socket', '/var/run/fail2ban/fail2ban.sock', 'ping'], 
                       check=True, capture_output=True)
        logger.info('Successfully connected to fail2ban socket')
    except subprocess.CalledProcessError as e:
        logger.error(f'Could not connect to fail2ban socket: {e.stderr.decode() if e.stderr else "Unknown error"}')
    except FileNotFoundError:
        logger.error('fail2ban-client not found. Make sure fail2ban-tools is installed.')
    except Exception as e:
        logger.error(f'Unexpected error checking fail2ban socket: {str(e)}')
    
    app.run(host='0.0.0.0', port=5000, debug=True)

