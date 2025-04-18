from dataclasses import dataclass, field
from typing import List

@dataclass
class Group:
    """Group model"""
    name: str
    sid: str
    memberof: List[str] = field(default_factory=list)  # List of user SIDs 
    members: List[str] = field(default_factory=list)
    
    def __str__(self) -> str:
        return f"""
        Name: {self.name}
        SID: {self.sid}
        memberof: {self.memberof}
        members: {self.members}
        """ 