"""
core/wordlist_generator.py - Smart Wordlist Generation
Generates context-aware wordlists for brute force and fuzzing
"""

import logging
from typing import List, Set, Tuple
import re

logger = logging.getLogger("recon.wordlist_generator")


class WordlistGenerator:
    """
    Smart wordlist generation using:
    - Company name variations
    - Discovered usernames
    - Year patterns
    - Common patterns (user+year, name+123, etc.)
    - Dictionary combinations
    """

    # Common password patterns
    COMMON_PATTERNS = [
        '{name}',
        '{name}123',
        '{name}!',
        '{name}@',
        '{name}2024',
        '{name}2025',
        '{name}2026',
        '{company}',
        '{company}123',
        '{company}!@#',
        'admin',
        'password',
        'admin123',
        'admin@123',
        'root',
        'test',
        'test123',
        '123456',
        'password123',
        'Welcome1',
        'Qwerty123',
        'Letmein',
        'Monkey123',
    ]

    # Common usernames
    COMMON_USERNAMES = [
        'admin',
        'administrator',
        'root',
        'test',
        'user',
        'guest',
        'wordpress',
        'wp-admin',
        'wp_admin',
        'webmaster',
        'master',
        'manager',
        'operator',
        'support',
        'info',
        'mail',
        'sales',
        'admin1',
        'admin2',
        'test1',
        'demo',
    ]

    def __init__(self):
        self.discovered_users = []
        self.company_name = ""
        self.domain_name = ""
        self.cache = {}

    def set_context(self, company_name: str = "", domain_name: str = "", discovered_users: List[str] = None):
        """Set context for wordlist generation"""
        self.company_name = company_name or ""
        self.domain_name = domain_name or ""
        self.discovered_users = discovered_users or []

    def generate_usernames(self, max_count: int = 100) -> List[str]:
        """
        Generate usernames wordlist
        """
        if 'usernames' in self.cache:
            return self.cache['usernames'][:max_count]

        usernames = set()

        # Add common usernames
        usernames.update(self.COMMON_USERNAMES)

        # Add discovered users
        usernames.update(self.discovered_users)

        # Add company variations
        if self.company_name:
            company_lower = self.company_name.lower()
            # Variations
            usernames.add(company_lower)
            usernames.add(company_lower + '_admin')
            usernames.add(company_lower + 'admin')
            usernames.add('admin_' + company_lower)
            
            # First letters
            if len(company_lower) > 2:
                usernames.add(company_lower[:3])
                usernames.add(company_lower[:4])

        # Add domain-based usernames
        if self.domain_name:
            domain_part = self.domain_name.split('.')[0].lower()
            usernames.add(domain_part)
            usernames.add(domain_part + '_admin')
            usernames.add('admin_' + domain_part)

        # Add generated first.last combinations
        generated = self._generate_fn_ln_combinations()
        usernames.update(generated)

        result = sorted(list(usernames))[:max_count]
        self.cache['usernames'] = result
        return result

    def generate_passwords(self, usernames: List[str] = None, max_count: int = 500) -> List[str]:
        """
        Generate passwords wordlist based on context
        """
        if 'passwords' in self.cache:
            return self.cache['passwords'][:max_count]

        passwords = set()

        # Common passwords
        base_passwords = [
            'admin', 'password', 'admin123', '123456', '12345678',
            'password123', 'admin@123', 'test123', 'root', 'root123',
            'qwerty', 'letmein', 'welcome', 'monkey', 'dragon',
            'master', 'sunshine', 'princess', 'shadow', 'michael',
            'superman', 'batman', 'starwars', 'password1', 'admin1',
        ]
        passwords.update(base_passwords)

        # Year-based variations
        years = ['2020', '2021', '2022', '2023', '2024', '2025', '2026']

        # Company variations
        if self.company_name:
            company_lower = self.company_name.lower()
            for pattern in self.COMMON_PATTERNS:
                if '{name}' in pattern:
                    passwords.add(pattern.replace('{name}', company_lower))
                if '{company}' in pattern:
                    passwords.add(pattern.replace('{company}', company_lower))

        # Username variations  
        if usernames:
            for username in usernames[:20]:  # Limit to first 20
                username_lower = username.lower()
                
                # Basic patterns
                passwords.add(username_lower)
                passwords.add(username_lower + '123')
                passwords.add(username_lower + '123!')
                passwords.add(username_lower + '!')
                passwords.add(username_lower + '@123')
                
                # Year patterns
                for year in years:
                    passwords.add(username_lower + year)
                    passwords.add(year + username_lower)

        # Special patterns
        for pattern in self.COMMON_PATTERNS:
            if '{name}' in pattern:
                if self.company_name:
                    passwords.add(pattern.replace('{name}', self.company_name.lower()))
            if '{company}' in pattern:
                if self.company_name:
                    passwords.add(pattern.replace('{company}', self.company_name.lower()))

        result = sorted(list(passwords))[:max_count]
        self.cache['passwords'] = result
        return result

    def generate_dirs(self, max_count: int = 100) -> List[str]:
        """
        Generate directory/endpoint wordlist
        """
        if 'directories' in self.cache:
            return self.cache['directories'][:max_count]

        dirs = set()

        # Common directories
        common = [
            'admin', 'administrator', 'login', 'auth', 'user', 'users',
            'upload', 'uploads', 'download', 'downloads', 'files',
            'api', 'v1', 'v2', 'v3', 'rest', 'graphql',
            'config', 'settings', 'backup', 'backups', 'old',
            'test', 'testing', 'debug', 'dev', 'development',
            'staging', 'prod', 'production', 'wp-admin', 'wp-content',
            'wp-includes', 'plugins', 'themes', 'templates',
            'public', 'private', 'secure', 'sensitive', 'secret',
            'data', 'database', 'db', 'sql', 'tmp', 'temp',
            'cache', 'log', 'logs', 'error', 'errors',
            'shell', 'cmd', 'exec', 'system', 'power',
            'dashboard', 'panel', 'control', 'manager', 'console',
            'image', 'images', 'photo', 'photos', 'media',
            'document', 'documents', 'doc', 'docs', 'pdf',
            'archive', 'compressed', 'zip', 'tar', 'gz',
            'source', 'src', 'code', 'app', 'lib', 'vendor',
            '.git', '.svn', '.env', 'config.php', 'web.config',
        ]
        dirs.update(common)

        # Company-based
        if self.company_name:
            company_lower = self.company_name.lower()
            dirs.add(company_lower)
            dirs.add(company_lower + '_admin')
            dirs.add('admin_' + company_lower)
            dirs.add(company_lower + '_backup')

        # Domain-based
        if self.domain_name:
            domain_part = self.domain_name.split('.')[0].lower()
            dirs.add(domain_part)
            dirs.add(domain_part + '_backup')

        result = sorted(list(dirs))[:max_count]
        self.cache['directories'] = result
        return result

    def generate_parameter_names(self, max_count: int = 100) -> List[str]:
        """
        Generate parameter names for fuzzing
        """
        params = [
            'id', 'user_id', 'username', 'email', 'password', 'pass',
            'login', 'auth', 'token', 'session', 'sid', 'jsessionid',
            'action', 'cmd', 'command', 'exec', 'execute', 'system',
            'query', 'q', 'search', 'keyword', 'filter', 'sort',
            'page', 'limit', 'offset', 'page_size', 'per_page',
            'url', 'redirect', 'next', 'continue', 'return',
            'file', 'filename', 'path', 'upload', 'upload_file',
            'data', 'content', 'body', 'message', 'text', 'comment',
            'category', 'type', 'sort', 'order', 'direction',
            'lang', 'language', 'locale', 'timezone', 'format',
            'callback', 'jsonp', 'json_callback', 'cors',
            'debug', 'verbose', 'log', 'trace', 'profile',
            'include', 'exclude', 'test', 'mode', 'config',
        ]
        return params[:max_count]

    def _generate_fn_ln_combinations(self, count: int = 20) -> List[str]:
        """Generate first name + last name combinations"""
        first_names = ['john', 'admin', 'test', 'demo', 'user', 'manager', 'operator']
        last_names = ['admin', 'user', 'test', 'doe', 'smith', 'operator']

        combos = []
        for fn in first_names[:5]:
            for ln in last_names[:5]:
                combos.append(f"{fn}_{ln}")
                combos.append(f"{fn}.{ln}")
                combos.append(f"{fn}{ln}")
                combos.append(f"{fn}.{ln[0]}")
        
        return combos

    def optimize_by_priority(self, wordlist: List[str], priority_keywords: List[str] = None) -> List[str]:
        """
        Prioritize wordlist by keywords
        """
        if not priority_keywords:
            return wordlist

        # Sort with priority keywords first
        def priority_key(word):
            for i, keyword in enumerate(priority_keywords):
                if keyword.lower() in word.lower():
                    return (i, word)
            return (len(priority_keywords), word)

        return sorted(wordlist, key=priority_key)
