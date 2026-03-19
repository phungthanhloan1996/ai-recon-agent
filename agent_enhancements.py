"""
Enhanced agent.py method additions - integrates all 10 improvements
This file contains new methods to add to agent.py for:
1. URL normalization
2. Endpoint analysis with HEAD/GET
3. Error recovery & self-reflection
4. Real exploitation
5. Conditional playbook execution
"""

# Add these methods to ReconAgent class in agent.py:

def _analyze_and_classify_endpoints(self):
    """
    IMPROVEMENT #3: Classify endpoints before attacking
    - Send HEAD/GET request
    - Analyze Content-Type
    - Detect forms
    - Classify into: static, html, json, api, upload
    """
    self.current_phase = "classify"
    self.phase_detail = "[CLASSIFY] Analyzing endpoints..."
    self.phase_tool = "endpoint-analyzer+head-request"
    self._update_display()
    
    endpoints = self.state.get("endpoints", [])
    classified = []
    upload_endpoints = []
    
    for endpoint in endpoints[:100]:  # Limit to first 100
        ep_url = endpoint.get('full_url') or endpoint.get('url')
        if not ep_url:
            continue
        
        # IMPROVEMENT: Analyze instead of blind attack
        try:
            analysis = self.endpoint_analyzer.analyze(ep_url, timeout=5)
            
            if analysis['reachable']:
                endpoint['type'] = analysis['endpoint_type']
                endpoint['content_type'] = analysis['content_type']
                endpoint['has_form'] = analysis['has_form']
                endpoint['forms'] = analysis['forms']
                endpoint['is_upload'] = analysis['is_upload']
                endpoint['confidence'] = analysis['confidence']
                
                # Track upload endpoints
                if analysis['is_upload']:
                    upload_endpoints.append(endpoint)
                
                classified.append(endpoint)
                
                # Log for batch display
                if self.batch_display:
                    detail = f"{analysis['endpoint_type']} ({analysis['status_code']})"
                    self.batch_display._add_to_feed("🤖", "Classified", ep_url[:25], detail)
        
        except Exception as e:
            self.error_recovery.log_error("classify", "endpoint-analyzer", str(e), {'url': ep_url})
            continue
    
    self.state.update(endpoints=classified, upload_endpoints=upload_endpoints)
    self.last_action = f"classified {len(classified)} endpoints"
    self._update_display()
    self._mark_phase_done("classify")

def _execute_real_exploitations(self):
    """
    IMPROVEMENT #4 & #6: Execute real attacks with recovery
    """
    self.current_phase = "exploit"
    self.phase_detail = "[EXPLOIT] Testing real vulnerabilities..."
    self.phase_tool = "exploit-executor"
    self._update_display()
    
    exploit_count = 0
    success_count = 0
    
    try:
        # Execute conditional playbook
        findings = {
            'found_wordpress': self.stats.get('wp', 0) > 0,
            'plugins': self.state.get('plugins', []),
            'has_upload_form': len(self.state.get('upload_endpoints', [])) > 0,
            'users': self.state.get('enumerated_users', []),
        }
        
        actions = self.playbook.execute_playbook(findings)
        
        for action in actions[:5]:  # Limit to 5 actions
            try:
                if action == 'test_file_upload':
                    upload_eps = self.state.get('upload_endpoints', [])
                    for upload_ep in upload_eps[:2]:
                        forms = upload_ep.get('forms', [])
                        for form in forms[:1]:
                            success, msg = self.exploit_executor.execute_upload_exploit(
                                self.target, form
                            )
                            exploit_count += 1
                            if success:
                                success_count += 1
                                self.stats['exploited'] += 1
                                self.phase_detail = f"[EXPLOIT] Upload successful: {msg}"
                
                elif action == 'wp_plugin_exploit':
                    wp_info = {'plugins': self.state.get('plugins', [])}
                    success, msg = self.exploit_executor.execute_wordpress_exploit(
                        self.target, wp_info
                    )
                    exploit_count += 1
                    if success:
                        success_count += 1
                        self.stats['exploited'] += 1
                        self.phase_detail = f"[EXPLOIT] WP Plugin compromised: {msg}"
                
                elif action == 'wp_xmlrpc_bruteforce':
                    # Generate wordlists
                    usernames = self.wordlist_gen.generate_usernames(50)
                    passwords = self.wordlist_gen.generate_passwords(usernames, 100)
                    self.phase_detail = f"[EXPLOIT] XMLRPC bruteforce (users:{len(usernames)}, pass:{len(passwords)})"
                    self._update_display()
                    
                    success, msg = self.exploit_executor._bruteforce_wordpress_xmlrpc(
                        f"{self.target}/xmlrpc.php", usernames
                    )
                    exploit_count += 1
                    if success:
                        success_count += 1
                        self.stats['exploited'] += 1
                
                self._update_display()
                
            except Exception as e:
                self.error_recovery.log_error("exploit", action, str(e))
                continue
        
        self.last_action = f"exploit: {success_count}/{exploit_count} successful"
        self._update_display()
        self._mark_phase_done("exploit")
        
        return success_count > 0
        
    except Exception as e:
        recovery = self.error_recovery.suggest_recovery("exploit", "executor", str(e))
        self.last_action = f"exploit error: {recovery['recommended_action']}"
        self.error_recovery.log_error("exploit", "executor", str(e))
        self._update_display()
        return False

def _run_phase_with_recovery(self, phase_name: str, phase_func, *args, **kwargs) -> bool:
    """
    IMPROVEMENT #8: Run any phase with automatic error recovery
    Wraps phase execution with self-reflection loop
    """
    max_retries = 2
    attempt = 0
    
    while attempt < max_retries:
        attempt += 1
        
        try:
            self.logger.info(f"[{phase_name}] Attempt {attempt}/{max_retries}")
            phase_func(*args, **kwargs)
            
            self.error_recovery.log_success(phase_name, "phase_executor")
            return True
            
        except Exception as e:
            error_msg = str(e)[:100]
            self.error_recovery.log_error(phase_name, "phase_executor", error_msg)
            
            recovery = self.error_recovery.suggest_recovery(phase_name, "phase_executor", error_msg)
            
            self.last_action = f"{phase_name}: {recovery['recommended_action']}"
            self._update_display()
            
            if recovery['skip'] or attempt >= max_retries:
                self.logger.warning(f"[{phase_name}] Skipping after {attempt} attempts")
                self.phase_status = "failed"
                self._update_display()
                return False
            
            if recovery['timeout_increase']:
                self.http_client.timeout += recovery['timeout_increase']
                self.logger.info(f"[{phase_name}] Increased timeout to {self.http_client.timeout}s")
            
            if recovery['backoff_seconds']:
                import time
                time.sleep(recovery['backoff_seconds'])
    
    return False

def _generate_smart_wordlists(self, company_name: str = ""):
    """
    IMPROVEMENT #5: Generate smart context-aware wordlists
    """
    if not company_name:
        company_name = self.target.replace(".com", "").replace(".net", "").replace(".org", "")
    
    self.wordlist_gen.set_context(
        company_name=company_name,
        domain_name=self.target,
        discovered_users=self.state.get('enumerated_users', [])
    )
    
    usernames = self.wordlist_gen.generate_usernames(100)
    passwords = self.wordlist_gen.generate_passwords(usernames, 500)
    directories = self.wordlist_gen.generate_dirs(100)
    parameters = self.wordlist_gen.generate_parameter_names(50)
    
    return {
        'usernames': usernames,
        'passwords': passwords,
        'directories': directories,
        'parameters': parameters
    }

def _check_endpoint_security(self, endpoint: Dict) -> Dict:
    """
    Before sending any payload:
    1. Check if endpoint type allows POST/PUT
    2. Parse forms
    3. Check for file uploads
    """
    ep_type = endpoint.get('type', 'unknown')
    
    # Don't send payloads to static files
    if not self.endpoint_analyzer.should_send_payload(ep_type):
        return {'safe_to_attack': False, 'reason': f'Static endpoint type: {ep_type}'}
    
    # Check forms
    forms = endpoint.get('forms', [])
    if forms:
        # Validate each form before sending data
        validated_forms = []
        for form in forms:
            # Check if form is safe to POST to
            if form.get('method', 'GET').upper() in ('POST', 'PUT', 'PATCH'):
                validated_forms.append(form)
        
        if validated_forms:
            return {'safe_to_attack': True, 'forms': validated_forms}
    
    # Check if endpoint accepts parameters
    if endpoint.get('has_query_params'):
        return {'safe_to_attack': True, 'params': endpoint.get('params', [])}
    
    return {'safe_to_attack': True, 'reason': 'Default endpoint'}
