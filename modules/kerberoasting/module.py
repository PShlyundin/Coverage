from typing import Dict, Any
from core.interfaces import IModule
from core.domain_state import DomainState
from core.utils import mask_password

class KerberoastingModule(IModule):
    def __init__(self):
        self._template_path = "template.md"
    
    @property
    def template_path(self) -> str:
        return self._template_path
    
    def run(self, domain_state: DomainState) -> Dict[str, Any]:
        """Run weak passwords check"""
        # Categorize users
        all_users = []
        
        for user in domain_state.users.values():
            if user.has_spn and user.sam_account_name != 'krbtgt':
                user_data = {
                    "username": user.sam_account_name,
                    "spn": user.spn_list,
                    "password": mask_password(user.cracked_password),
                    "is_domain_admin": domain_state.is_domain_admin(user.object_sid)
                }
                all_users.append(user_data)
        
        if not all_users:
            return {}
        return {
            "template": self.template_path,
            "all_users": all_users,
            "total_found": len(all_users)
        }