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
logging.basicConfig(level=logging.WARNING)  # Reduced from INFO to WARNING

# Get environment variables
USERNAME = os.getenv('FAIL2WEB_USERNAME', 'admin')
PASSWORD = os.getenv('FAIL2WEB_PASSWORD', 'admin')
jail_d_path = '/data/jail.d'  # Path to jail.d directory in container

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        
        if not auth_header:
            return jsonify({'error': 'Token is missing'}), 401
        
        # Extract token from "Bearer <token>" format or handle direct token
        try:
            if auth_header.startswith('Bearer '):
                token = auth_header[7:]  # Remove 'Bearer ' prefix
            elif ' ' in auth_header:
                # Handle other "scheme token" formats
                token = auth_header.split(' ')[1]
            else:
                # Direct token without prefix
                token = auth_header
        except Exception as e:
            return jsonify({'error': 'Invalid token format'}), 401
        
        if not token:
            return jsonify({'error': 'Token is empty'}), 401
        
        try:
            decoded = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
            # PyJWT automatically validates expiration when decode() is called
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        except Exception:
            return jsonify({'error': 'Token validation failed'}), 401
        
        g.current_user = decoded['sub']
        return f(*args, **kwargs)
    return decorated

def fail2ban_command(cmd):
    try:
        # Use the correct socket path that fail2ban is actually using
        socket_path = '/var/run/fail2ban/fail2ban.sock'
        command = ['fail2ban-client', '--socket', socket_path] + cmd.split()
        
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False  # Don't raise exception on non-zero exit
        )
        
        stdout = result.stdout.strip()
        stderr = result.stderr.strip()
        
        if result.returncode != 0:
            logger.error(f"Command failed with return code {result.returncode}: {stderr}")
            return None  # Indicate failure
        
        # Parse jail list from status command
        if cmd == 'status':
            lines = stdout.split('\n')
            jails = []
            
            # First, try to extract from any line containing "Jail list:"
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                    
                # Look for any line containing "Jail list:" (case insensitive)
                # Handle formats like "`- Jail list:	sshd" or "Jail list: sshd"
                if 'jail list:' in line.lower():
                    # Extract everything after "Jail list:" (case insensitive)
                    import re
                    match = re.search(r'jail list:\s*(.+)', line, re.IGNORECASE)
                    if match:
                        jail_list_part = match.group(1).strip()
                        
                        # Split by spaces, commas, tabs, or other whitespace
                        jail_names = re.split(r'[,\s\t]+', jail_list_part)
                        for jail in jail_names:
                            jail = jail.strip()
                            if jail and jail.lower() not in ['', 'none', 'jails']:
                                jails.append(jail)
                        break  # Found jail list line, we're done
            
            # If still no jails found, try other parsing methods
            if not jails:
                for line in lines:
                    line = line.strip()
                    if not line:
                        continue
                    
                    # Skip header lines and status lines
                    line_lower = line.lower()
                    if (line_lower.startswith('number of jail') or 
                        line_lower.startswith('status') or
                        'total' in line_lower or
                        line in ['-', '|', '`']):
                        continue
                    
                    # Try to parse jail names from various formats
                    
                    # Format 1: "1-sshd" or "`- sshd" (numbered or bulleted list)
                    if '-' in line:
                        # Remove any bullet characters first
                        clean_line = re.sub(r'^[`|\-]+\s*', '', line)
                        parts = clean_line.split('-')
                        if len(parts) >= 2:
                            jail_name = parts[1].strip()
                            if jail_name and jail_name.lower() not in ['-', 'total', 'number', 'jail']:
                                jails.append(jail_name)
                        elif len(parts) == 1 and clean_line:
                            # Might be just a jail name after bullet
                            jail_name = clean_line.strip()
                            if jail_name and re.match(r'^[a-zA-Z0-9_-]+$', jail_name):
                                jails.append(jail_name)
                    
                    # Format 2: Just a jail name (like "sshd")
                    elif line and line.lower() not in ['-', 'total', 'number', 'jail']:
                        # Remove any bullet characters
                        clean_line = re.sub(r'^[`|\-]+\s*', '', line)
                        if clean_line and re.match(r'^[a-zA-Z0-9_-]+$', clean_line):
                            jails.append(clean_line)
            
            # Remove duplicates and return
            unique_jails = []
            for jail in jails:
                if jail and jail not in unique_jails:
                    unique_jails.append(jail)
            
            return unique_jails if unique_jails else []
        
        return stdout
    except FileNotFoundError:
        logger.error(f"fail2ban-client command not found. Is fail2ban installed and in PATH?")
        return None
    except Exception as e:
        logger.error(f"Error executing fail2ban command: {e}")
        return None

@app.route('/')
def index():
    return send_from_directory('../frontend', 'index.html')

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if username == USERNAME and password == PASSWORD:
            # Generate JWT token with explicit algorithm
            payload = {
                'sub': username,
                'exp': datetime.utcnow() + app.config['JWT_ACCESS_TOKEN_EXPIRES'],
                'iat': datetime.utcnow()
            }
            token = jwt.encode(payload, app.config['JWT_SECRET_KEY'], algorithm='HS256')
            
            # Ensure token is string (not bytes)
            if isinstance(token, bytes):
                token = token.decode('utf-8')
            
            return jsonify({
                'token': token,
                'expires_in': '24 hours'
            })
        else:
            logger.warning(f"Invalid credentials for user: {username}")
            return jsonify({'error': 'Invalid credentials'}), 401
            
    except Exception as e:
        logger.error(f"Error in login: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/jails')
@token_required
def get_jails():
    try:
        jails = fail2ban_command('status')
        if jails is None:
            logger.error("Unable to communicate with fail2ban")
            return jsonify({'error': 'Failed to communicate with fail2ban. Check if fail2ban is running and socket is accessible.'}), 500
        return jsonify({'jails': jails if isinstance(jails, list) else []})
    except Exception as e:
        logger.error(f"Error in get_jails: {str(e)}")
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
        # Stop fail2ban completely
        stop_response = fail2ban_command('stop')
        
        # Wait for stop to complete
        time.sleep(2)
        
        # Start fail2ban (will auto-read new configs)
        start_response = fail2ban_command('start')
        
        # Wait for startup and verify
        time.sleep(3)
        status_response = fail2ban_command('status')
        jail_active = jail_name in str(status_response) if status_response else False
        
        if not jail_active:
            # Try alternative start method
            fail2ban_command(f'start {jail_name} --once')
        
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

# Template functionality removed - not used in current implementation
# Jail creation uses smart defaults and manual configuration instead

@app.route('/api/ignoreip', methods=['GET'])
@token_required
def get_ignoreip():
    try:
        ignoreip_file = Path(jail_d_path) / 'ignoreIP.conf'
        
        # If file doesn't exist, create it with default IPs
        if not ignoreip_file.exists():
            # Default IPs that should never be banned
            default_ips = [
                '127.0.0.1/8',    # localhost
                '::1',            # IPv6 localhost
                '192.168.0.0/16', # private network
                '10.0.0.0/8',     # private network
                '172.16.0.0/12'   # private network
            ]
            
            config = configparser.ConfigParser()
            ignoreip_text = '\n            '.join(default_ips)
            config['DEFAULT']['ignoreip'] = ignoreip_text
            
            ignoreip_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(ignoreip_file, 'w') as f:
                config.write(f)
            
            return jsonify({'ignoreip': default_ips})
        
        # File exists, read it
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
        
        if not data or 'ignoreip' not in data:
            return jsonify({'error': 'Missing ignoreip field in request'}), 400
            
        ignoreip_list = data.get('ignoreip', [])
        
        if not isinstance(ignoreip_list, list):
            return jsonify({'error': 'ignoreip must be a list'}), 400
        
        # More permissive IP and CIDR validation
        # Accepts IPv4 (192.168.1.1), IPv6 (::1), and CIDR notation
        ipv4_regex = r'^(\d{1,3}\.){3}\d{1,3}$'
        ipv6_regex = r'^([0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}$|^::1$|^::$'
        cidr_regex = r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
        ipv6_cidr_regex = r'^([0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}/\d{1,3}$|^::/\d{1,3}$|^::1/\d{1,3}$'
        
        validated_ips = []
        for ip in ignoreip_list:
            if not ip or not isinstance(ip, str):
                continue
                
            ip = ip.strip()
            if not ip:
                continue
            
            # Check if it matches IP or CIDR pattern
            if (re.match(ipv4_regex, ip) or re.match(ipv6_regex, ip) or 
                re.match(cidr_regex, ip) or re.match(ipv6_cidr_regex, ip)):
                
                # Determine if it's IPv4 or IPv6
                is_ipv4 = re.match(ipv4_regex, ip) or re.match(cidr_regex, ip)
                is_ipv6 = re.match(ipv6_regex, ip) or re.match(ipv6_cidr_regex, ip)
                
                if '/' in ip:
                    # CIDR notation - validate IP part and CIDR mask
                    ip_part, mask_part = ip.split('/')
                    valid = True
                    
                    if is_ipv4:
                        # IPv4 CIDR - validate octets (0-255) and mask (0-32)
                        octets = ip_part.split('.')
                        for octet in octets:
                            if not octet.isdigit() or int(octet) > 255:
                                valid = False
                                break
                        
                        # Validate CIDR mask (0-32)
                        if valid and mask_part.isdigit():
                            mask = int(mask_part)
                            if mask < 0 or mask > 32:
                                valid = False
                        else:
                            valid = False
                    else:
                        # IPv6 CIDR - validate mask (0-128)
                        if mask_part.isdigit():
                            mask = int(mask_part)
                            if mask < 0 or mask > 128:
                                valid = False
                        else:
                            valid = False
                            
                    if valid:
                        validated_ips.append(ip)
                    else:
                        error_msg = f'Invalid CIDR format: {ip}'
                        if is_ipv4:
                            error_msg += '. IPv4 CIDR mask must be 0-32.'
                        else:
                            error_msg += '. IPv6 CIDR mask must be 0-128.'
                        logger.warning(error_msg)
                        return jsonify({'error': error_msg}), 400
                else:
                    # Regular IP (no CIDR)
                    if is_ipv4:
                        # IPv4 - validate octets (0-255)
                        octets = ip.split('.')
                        valid = True
                        for octet in octets:
                            if not octet.isdigit() or int(octet) > 255:
                                valid = False
                                break
                        if valid:
                            validated_ips.append(ip)
                        else:
                            logger.warning(f"Invalid IPv4 octet range: {ip}")
                            return jsonify({'error': f'Invalid IPv4 octet range: {ip}'}), 400
                    else:
                        # IPv6 - already validated by regex, accept it
                        validated_ips.append(ip)
            else:
                logger.warning(f"Invalid IP/CIDR format: {ip}")
                return jsonify({'error': f'Invalid IP/CIDR format: {ip}'}), 400
        
        # Add default IPs that should never be banned
        default_ips = [
            '127.0.0.1/8',    # localhost
            '::1',            # IPv6 localhost
            '192.168.0.0/16', # private network
            '10.0.0.0/8',     # private network
            '172.16.0.0/12'   # private network
        ]
        
        # Merge user IPs with defaults, removing duplicates
        all_ips = list(dict.fromkeys(default_ips + validated_ips))
        
        config = configparser.ConfigParser()
        # DEFAULT section exists automatically in ConfigParser
        # Don't call add_section('DEFAULT') - it's reserved
        ignoreip_text = '\n            '.join(all_ips)
        config['DEFAULT']['ignoreip'] = ignoreip_text
        
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

@app.route('/api/filters/<filter_name>')
@token_required
def get_filter_content(filter_name):
    try:
        # Paths for filter configuration files based on docker-compose mounts
        # Filter files are mounted at /data/fail2ban/filter.d/ in fail2web container
        possible_paths = [
            # Docker mount path (from docker-compose.yml)
            Path('/data/fail2ban/filter.d') / f'{filter_name}.conf',
            Path('/data/fail2ban/filter.d') / filter_name,
            # Original development path
            Path('/data/filter.d') / f'{filter_name}.conf',
            Path('/data/filter.d') / filter_name,
            # Standard fail2ban paths
            Path('/etc/fail2ban/filter.d') / f'{filter_name}.conf',
            Path('/etc/fail2ban/filter.d') / filter_name,
            Path('/usr/share/fail2ban/filter.d') / f'{filter_name}.conf',
            Path('/usr/share/fail2ban/filter.d') / filter_name,
        ]
        
        filter_path = None
        for path in possible_paths:
            if path.exists():
                filter_path = path
                break
        
        if not filter_path:
            # Filter not found in any location
            logger.warning(f"Filter {filter_name} not found in any location")
            return jsonify({
                'status': 'not_found',
                'message': f'Filter {filter_name} configuration not available. Check if filter file exists in /data/fail2ban/filter.d/.',
                'filter': filter_name
            })
        
        # Read filter content
        with open(filter_path, 'r') as f:
            content = f.read()
        
        return jsonify({
            'status': 'success',
            'content': content,
            'filter': filter_name,
            'path': str(filter_path)
        })
        
    except Exception as e:
        logger.error(f"Error reading filter {filter_name}: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/verify-token')
@token_required
def verify_token():
    try:
        # Token is already validated by @token_required decorator
        return jsonify({'valid': True, 'user': g.current_user})
    except Exception as e:
        logger.error(f"Error verifying token: {str(e)}")
        return jsonify({'error': str(e)}), 401


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
