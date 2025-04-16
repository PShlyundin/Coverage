from dataclasses import dataclass, field
from typing import List

@dataclass
class Group:
    """Group model"""
    name: str
    sid: str
    members: List[str] = field(default_factory=list)  # List of user SIDs 

    def __str__(self) -> str:
        return f"""
        Name: {self.name}
        SID: {self.sid}
        Members: {self.members}
        """ 