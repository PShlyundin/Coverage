from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class Computer:
    """Computer model"""
    sam_account_name: Optional[str] = None
    distinguished_name: Optional[str] = None
    spn_list: List[str] = field(default_factory=list)  # List of Service Principal Names
    object_sid: Optional[str] = None
    nt_hash: Optional[str] = None  # Hash from secretsdump
    lm_hash: Optional[str] = None  # Hash from secretsdump
    clear_text_password: Optional[str] = None  # Clear text password from secretsdump
    cracked_password: Optional[str] = None  # Cracked password from hashcat
    enabled: bool = True
    memberof: List[str] = field(default_factory=list)  # List of group SIDs
    user_account_control: int = 0
    user_with_domain: Optional[str] = None
    description: Optional[str] = None
    members: List[str] = field(default_factory=list)
    @property
    def has_spn(self) -> bool:
        return len(self.spn_list) > 0

    @property
    def password_cracked(self) -> bool:
        return self.cracked_password is not None 
    
    def __str__(self) -> str:
        return f"""
        SamAccountName: {self.sam_account_name}
        DistinguishedName: {self.distinguished_name}
        SPNs: {self.spn_list}
        ObjectSID: {self.object_sid}
        Enabled: {self.enabled}
        MemberOf: {self.memberof}
        UserAccountControl: {self.user_account_control}
        Description: {self.description}
        Members: {self.members}
        NT Hash: {self.nt_hash}
        LM Hash: {self.lm_hash}
        Clear Text Password: {self.clear_text_password}
        Cracked Password: {self.cracked_password}
        """