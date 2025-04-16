from typing import Dict, Any
from core.interfaces import IModule
from core.domain_state import DomainState

class KerberoastingModule(IModule):
    def __init__(self):
        self._template_path = "template.md"
    
    @property
    def template_path(self) -> str:
        return self._template_path
    
    def run(self, domain_state: DomainState) -> Dict[str, Any]:
        """Run weak passwords check"""
        # Разделяем пользователей по категориям
        domain_admin_users = []
        regular_users = []
        disabled_users = []
        
        for user in domain_state.users.values():
            if user.password_cracked:
                user_data = {
                    "username": user.sam_account_name,
                    "password": mask_password(user.cracked_password),
                    "is_domain_admin": domain_state.is_domain_admin(user.object_sid),
                    "enabled": user.enabled
                }
                
                if domain_state.is_domain_admin(user.object_sid):
                    domain_admin_users.append(user_data)
                elif user.enabled:
                    regular_users.append(user_data)
                else:
                    disabled_users.append(user_data)
        
        # Объединяем все категории в один список с сохранением порядка
        all_users = domain_admin_users + regular_users + disabled_users
        
        if not all_users:
            return {}
            
        return {
            "template": self.template_path,
            "all_users": all_users,
            "total_found": len(all_users)
        } 