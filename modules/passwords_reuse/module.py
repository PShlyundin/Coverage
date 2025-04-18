from typing import Dict, Any, List, Set
from core.interfaces import IModule
from core.domain_state import DomainState
from core.utils import mask_password

class PasswordsReuseModule(IModule):
    def __init__(self):
        self._template_path = "template.md"
    
    @property
    def template_path(self) -> str:
        return self._template_path
    
    def run(self, domain_state: DomainState) -> Dict[str, Any]:
        """Run password reuse check with admin accounts"""
        # Dictionary to store hashes and corresponding accounts
        hash_to_accounts: Dict[str, List[str]] = {}
        
        # Collect all accounts with hashes
        for user in domain_state.users.values():
            if user.nt_hash:
                if user.nt_hash not in hash_to_accounts:
                    hash_to_accounts[user.nt_hash] = []
                hash_to_accounts[user.nt_hash].append(user.sam_account_name)
        
        # List to store results
        password_reuse = []
        
        # Check each hash
        for nt_hash, accounts in hash_to_accounts.items():
            # If there is more than one account with this hash
            if len(accounts) > 1:
                # Get password for display
                first_user = domain_state.find_by_sam_account_name(accounts[0])
                password = mask_password(first_user.cracked_password) if first_user and first_user.cracked_password else "Not cracked"
                
                # Check if there are administrative accounts among them
                admin_accounts = [acc for acc in accounts if domain_state.is_domain_admin(acc)]
                
                # If there is at least one admin account
                if admin_accounts:
                    for admin_acc in admin_accounts:
                        # Collect all accounts with the same hash, except current admin
                        reuse_accounts = [acc for acc in accounts if acc != admin_acc]
                        
                        password_reuse.append({
                            "admin_account": admin_acc,
                            "reuse_accounts": reuse_accounts,
                            "password": password,
                            "is_cracked": first_user and first_user.cracked_password is not None
                        })
        
        # Sort results: first cracked passwords, then others
        password_reuse.sort(key=lambda x: (not x["is_cracked"], x["admin_account"]))
        
        if not password_reuse:
            return {}
        return {
            "template": self.template_path,
            "password_reuse": password_reuse,
            "total_found": len(password_reuse)
        }