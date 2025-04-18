import re
import hashlib
from typing import Dict, List, Any, Tuple
from core.domain_state import DomainState
from core.interfaces import IModule
from core.utils import mask_password
class PasswordsInDescriptionModule(IModule):
    def __init__(self):
        self._template_path = "template.md"
    
    @property
    def template_path(self) -> str:
        return self._template_path
    
    def _extract_potential_passwords(self, description: str) -> List[str]:
        """
        Extract potential passwords from description using various patterns
        """
        passwords = []
        
        # Common patterns for passwords in descriptions
        patterns = [
            r'password\s*[=:]\s*([^\s]+)',  # password = value or password:value
            r'pass\s*[=:]\s*([^\s]+)',      # pass = value or pass:value
            r'pwd\s*[=:]\s*([^\s]+)',       # pwd = value or pwd:value
            r'\(([^)]+)\)',                 # (password)
            r'\[([^\]]+)\]',               # [password]
            r'\{([^}]+)\}',                # {password}
            r'"([^"]+)"',                   # "password"
            r"'([^']+)'",                   # 'password'
            r'`([^`]+)`',                   # `password`
            r'\\"([^\\"]+)\\"',            # \"password\"
            r"\\'([^\\']+)\\'",            # \'password\'
            r'\\`([^\\`]+)\\`',            # \`password\`
            r'\\\(([^\\()]+)\\\)',         # \(password\)
            r'\\\[([^\\[\]]+)\\\]',        # \[password\]
            r'\\\{([^\\{}]+)\\\}',         # \{password\}
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, description, re.IGNORECASE)
            for match in matches:
                potential_password = match.group(1)
                # Basic validation to avoid false positives
                if len(potential_password) >= 8 and any(c.isupper() for c in potential_password) and any(c.islower() for c in potential_password) and any(c.isdigit() for c in potential_password):
                    passwords.append(potential_password)
        
        return passwords
    
    def _calculate_ntlm_hash(self, password: str) -> str:
        """
        Calculate NTLM hash for a given password
        """
        # Convert password to bytes
        password_bytes = password.encode('utf-16le')
        
        # Calculate MD4 hash
        md4_hash = hashlib.new('md4', password_bytes).hexdigest()
        
        return md4_hash
    
    def run(self, domain_state: DomainState) -> Dict[str, Any]:
        """
        Check for passwords in user descriptions
        """
        findings = []
        
        # Process users
        for user in domain_state.users.values():
            if not user.description:
                continue
                
            # Extract potential passwords from description
            potential_passwords = self._extract_potential_passwords(user.description)
            
            # Check each potential password against user's NTLM hash
            for password in potential_passwords:
                ntlm_hash = self._calculate_ntlm_hash(password)

                if ntlm_hash == user.nt_hash:
                    findings.append({
                        "account": user.sam_account_name,
                        "password": mask_password(password),
                        "is_admin": domain_state.is_domain_admin(user.object_sid),
                        "is_enabled": user.enabled,
                        "description": user.description
                    })
                    break  # Found matching password, no need to check others
        
        # Sort findings: admins first, then enabled accounts, then disabled
        findings.sort(key=lambda x: (
            not x["is_admin"],  # True sorts after False, so we negate
            not x["is_enabled"],  # True sorts after False, so we negate
            x["account"]  # Secondary sort by account name
        ))
        
        if not findings:
            return {}
            
        return {
            "template": self.template_path,
            "passwords_in_description": findings,
            "total_found": len(findings)
        } 