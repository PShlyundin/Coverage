from typing import Dict, List, Any
from core.domain_state import DomainState
from core.utils import mask_password
from core.interfaces import IModule

class ReversibleEncryptionModule(IModule):
    def __init__(self):
        self._template_path = "template.md"
    
    @property
    def template_path(self) -> str:
        return self._template_path
    
    def run(self, domain_state: DomainState) -> Dict[str, Any]:
        """
        Check for accounts with reversible encryption enabled
        """
        findings = []
        
        # Process users
        for user in domain_state.users.values():
            if user.clear_text_password:
                findings.append({
                    "account": user.sam_account_name,
                    "password": mask_password(user.clear_text_password),
                    "is_admin": domain_state.is_domain_admin(user.object_sid),
                    "is_enabled": user.enabled,
                    "type": "USER"
                })
        
        # Process computers
        for computer in domain_state.computers.values():
            if computer.clear_text_password:
                findings.append({
                    "account": computer.sam_account_name,
                    "password": mask_password(computer.clear_text_password),
                    "is_admin": domain_state.is_domain_admin(computer.object_sid),
                    "is_enabled": computer.enabled,
                    "type": "COMPUTER"
                })
        
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
            "reversible_encryption": findings,
            "total_found": len(findings)
        } 