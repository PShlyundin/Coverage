from typing import Dict, Any
from core.interfaces import IModule
from core.domain_state import DomainState
from core.utils import mask_password

class WeakPasswordsModule(IModule):
    def __init__(self):
        self._template_path = "template.md"
    
    @property
    def template_path(self) -> str:
        return self._template_path
    
    def run(self, domain_state: DomainState) -> Dict[str, Any]:
        """Run weak passwords check"""
        weak_password_users = []
        
        for user in domain_state.users.values():
            if user.password_cracked and user.enabled:
                weak_password_users.append({
                    "username": user.sam_account_name,
                    "password": mask_password(user.cracked_password),
                    "is_domain_admin": domain_state.is_domain_admin(user.object_sid),
                    "enabled": user.enabled
                })
        print(f"Weak passwords: {weak_password_users}")
        if not weak_password_users:
            return {}
            
        return {
            "template": self.template_path,
            "weak_password_users": weak_password_users,
            "total_found": len(weak_password_users)
        } 