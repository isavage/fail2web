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
        return add_cors_headers(jsonify({'error': str(e)}), 500)
