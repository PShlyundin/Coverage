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
        
        admin_users = []
        for user in domain_state.users.values():
            if user.password_cracked and domain_state.is_domain_admin(user.sam_account_name):
                admin_users.append({
                    "username": user.sam_account_name,
                    "password": mask_password(user.cracked_password),
                    "is_domain_admin": domain_state.is_domain_admin(user.sam_account_name),
                    "enabled": user.enabled
                })
        weak_password_users = admin_users
        enabled_users = []
        for user in domain_state.users.values():
            if user.password_cracked and user.enabled and not user.sam_account_name in [e['username'] for e in weak_password_users]:
                enabled_users.append({
                    "username": user.sam_account_name,
                    "password": mask_password(user.cracked_password),
                    "is_domain_admin": domain_state.is_domain_admin(user.sam_account_name),
                    "enabled": user.enabled
                })
        weak_password_users = weak_password_users + enabled_users
        other_users = []
        for user in domain_state.users.values():
            if user.password_cracked and not user.enabled and not user.sam_account_name in [e['username'] for e in weak_password_users]:
                other_users.append({
                    "username": user.sam_account_name,
                    "password": mask_password(user.cracked_password),
                    "is_domain_admin": domain_state.is_domain_admin(user.sam_account_name),
                    "enabled": user.enabled
                })
        weak_password_users = weak_password_users + other_users

        if not weak_password_users:
            return {}
            
        return {
            "template": self.template_path,
            "weak_password_users": weak_password_users,
            "total_found": len(weak_password_users)
        } 