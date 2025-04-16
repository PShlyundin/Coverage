from typing import Dict, Optional, List, Set
from models.user import User
from models.group import Group
from models.computer import Computer
from core.utils import is_sid_in_domain_admin_groups

class DomainState:
    """Class for storing domain state"""
    def __init__(self):
        self.users: Dict[str, User] = {}  # key - SAM Account Name
        self.groups: Dict[str, Group] = {}  # key - SID
        self.computers: Dict[str, Computer] = {}  # key - SID
        self.sid_to_sam: Dict[str, str] = {}  # mapping SID -> SAM Account Name
        self.sam_to_sid: Dict[str, str] = {}  # mapping SAM Account Name -> SID
        self.hash_to_sid: Dict[str, str] = {}  # mapping NT Hash -> SID
        self._domain_sid: Optional[str] = None  # Cached domain SID
        
    @property
    def domain_sid(self) -> str:
        """Extract domain SID from any user or computer SID. Lazy Initialization"""
        if self._domain_sid is None or self._domain_sid == "S-1-5-21":
            # Try to find a SID from users
            for user in self.users.values():
                if user.object_sid:
                    self._domain_sid = '-'.join(user.object_sid.split('-')[:-1])
                    break
            
            # If not found in users, try computers
            if self._domain_sid is None:
                for computer in self.computers.values():
                    if computer.object_sid:
                        self._domain_sid = '-'.join(computer.object_sid.split('-')[:-1])
                        break
            
            # If still not found, use a default
            if self._domain_sid is None:
                self._domain_sid = "S-1-5-21"  # Default domain SID
        
        return self._domain_sid
        
    def add_user(self, user: User) -> None:
        """Add user to state"""
        self.users[user.sam_account_name] = user
        self.sid_to_sam[user.object_sid] = {'object_type': 'user', 'name': user.sam_account_name}   
        self.sam_to_sid[user.sam_account_name] = user.object_sid
        if user.nt_hash:
            self.hash_to_sid[user.nt_hash] = user.object_sid

    def add_group(self, group: Group) -> None:
        """Add group to state"""
        self.groups[group.name] = group
        self.sam_to_sid[group.name] = group.sid
        self.sid_to_sam[group.sid] = {'object_type': 'group', 'name': group.name}

    def add_computer(self, computer: Computer) -> None:
        """Add computer to state"""
        self.computers[computer.sam_account_name] = computer
        self.sid_to_sam[computer.object_sid] = {'object_type': 'computer', 'name': computer.sam_account_name}
        if computer.nt_hash:
            self.hash_to_sid[computer.nt_hash] = computer.object_sid

    def update_user_password(self, nt_hash: str, password: str) -> None:
        """Update user password by hash
        
        Args:
            nt_hash: NT hash to find users/computers with
            password: Cracked password to set
        """
        # Update users with matching hash
        for user in self.users.values():
            if user.nt_hash == nt_hash:
                user.cracked_password = password
                
        # Update computers with matching hash
        for computer in self.computers.values():
            if computer.nt_hash == nt_hash:
                computer.cracked_password = password

    def is_domain_admin(self, user_sid: str) -> bool:
        """Check if user is domain admin
        
        This method recursively checks if the user is a member of:
        - Domain Admins group
        - Administrators group
        - Enterprise Admins group
        
        Args:
            user_sid: User SID to check
            
        Returns:
            True if user is a domain admin
        """
        if not self.domain_sid:
            return False
            
        return is_sid_in_domain_admin_groups(user_sid, self.domain_sid, self.groups)

    def find_by_sam_account_name(self, sam_account_name: str) -> Optional[User]:
        """Find user by SAM Account Name"""
        user = self.users.get(sam_account_name)
        if user:
            return user
        computer = self.computers.get(sam_account_name)
        if computer:
            return computer
        return None
    
    def find_by_sid(self, sid: str) -> Optional[User]:
        """Find user by SID"""
        sam_account_name = self.sid_to_sam.get(sid)
        user = self.find_by_sam_account_name(sam_account_name)  
        if user:
            return user
        computer = self.computers.get(sam_account_name)
        if computer:
            return computer
        return None    
    
    def print_users(self) -> None:
        """Print all users"""
        print(f"users: {self.users['c221']}")
    
