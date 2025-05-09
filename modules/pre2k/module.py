from typing import Dict, Any
from core.interfaces import IModule
from core.domain_state import DomainState
from core.utils import mask_password
from Crypto.Hash import MD4
import binascii

class Pre2kModule(IModule):
    def __init__(self):
        self._template_path = "template.md"
    
    @property
    def template_path(self) -> str:
        return self._template_path
    
    def get_hash(self, password: str) -> str:
        """Calculate MD4 hash of password"""
        md4 = MD4.new()
        md4.update(password.encode("utf-16le"))
        return md4.hexdigest()

    def run(self, domain_state: DomainState) -> Dict[str, Any]:
        """Run Pre-2000 compatibility check"""
        # List of users with Pre-2000 compatibility
        all_users = []
        enabled = []
        disabled = []
        for comp_name, computer in domain_state.computers.items():
            if self.get_hash(computer.sam_account_name.replace("$", "").lower()) == computer.nt_hash:
                if computer.enabled:
                    enabled.append({
                        "username": computer.sam_account_name,
                        "password": computer.sam_account_name.replace("$", ""),
                        "status": computer.enabled
                    })
                else:
                    disabled.append({
                        "username": computer.sam_account_name,
                        "password": computer.sam_account_name.replace("$", ""),
                        "status": computer.enabled
                    })
        all_users = enabled + disabled
        
        if not all_users:
            return {}
        return {
            "template": self.template_path,
            "all_users": all_users,
            "total_found": len(all_users)
        }