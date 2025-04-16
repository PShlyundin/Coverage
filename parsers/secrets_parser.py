from typing import Dict, Any, Tuple, Optional, List
from dataclasses import dataclass
from core.interfaces import IParser
from core.domain_state import DomainState
from core.exceptions import ValidationError
from models.user import User
from models.computer import Computer

@dataclass
class NTDSEntry:
    """Data class for NTDS entries"""
    sam_account_name: str  # Can include domain prefix (e.g. domain.local\username)
    rid: str
    clear_text_password: Optional[str] = None
    lm_hash: Optional[str] = None
    nt_hash: Optional[str] = None

    @property
    def username(self) -> str:
        """Get username without domain prefix"""
        return self.sam_account_name.split('\\')[-1]

class SecretsParser(IParser):
    """Parser for NTDS.dit dump files"""
    def __init__(self, ntds_paths: List[str]):
        self.ntds_paths = ntds_paths
        self.data: List[NTDSEntry] = []

    def load_data(self) -> None:
        """Load NTDS data from files"""
        for ntds_path in self.ntds_paths:
            try:
                if ntds_path.endswith('.kerberos'):
                    continue  # Skip kerberos files for now
                
                file_type = 'cleartext' if ntds_path.endswith('.cleartext') else 'ntds'
                with open(ntds_path, 'r') as f:
                    for line in f:
                        entry = self._parse_line(line, file_type)
                        if entry:
                            self.data.append(entry)
            except Exception as e:
                raise ValidationError(f"Failed to load NTDS data from {ntds_path}: {str(e)}")

    def _parse_line(self, line: str, file_type: str) -> Optional[NTDSEntry]:
        """Parse single line from NTDS file
        
        For .ntds files:
        Expected format: domain.local\SamAccountName:rid:LM_hash:NT_hash
        Example: domain.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
        
        For .ntds.cleartext files:
        Expected format: domain.local\SamAccountName:CLEARTEXT:password
        Example: domain.local\admin:CLEARTEXT:P@ssw0rd
        """
        try:
            line = line.strip()
            if not line:
                return None

            # Split by : and handle domain prefix
            parts = line.split(':')
            if len(parts) < 3:
                return None

            # Extract sam_account_name (can include domain prefix)
            sam_account_name = parts[0]
            rid = parts[1]

            if file_type == 'cleartext':
                if parts[1] != 'CLEARTEXT':
                    return None
                return NTDSEntry(
                    sam_account_name=sam_account_name,
                    rid=rid,
                    clear_text_password=parts[2]
                )
            else:  # ntds
                if len(parts) < 4:
                    return None
                return NTDSEntry(
                    sam_account_name=sam_account_name,
                    rid=rid,
                    lm_hash=parts[2],
                    nt_hash=parts[3]
                )
        except Exception:
            return None

    def validate_format(self) -> bool:
        """Validate NTDS format"""
        try:
            self.load_data()
            if not self.data:
                print("Warning: No valid entries found in NTDS files")
                return False
            
            # Check first entry format
            entry = self.data[0]
            if entry.clear_text_password is not None:
                if not isinstance(entry.clear_text_password, str) or len(entry.clear_text_password) < 1:
                    print("Warning: Invalid password format in NTDS file")
                    return False
            elif entry.nt_hash is not None:
                if not isinstance(entry.nt_hash, str) or len(entry.nt_hash) != 32:
                    print("Warning: Invalid hash format in NTDS file")
                    return False
            
            return True
        except Exception as e:
            print(f"Invalid NTDS format: {str(e)}")
            return False

    def parse(self, domain_state: DomainState) -> None:
        """Parse NTDS data and update domain state"""
        for entry in self.data:
            try:
                # Find object by SAM account name
                obj = domain_state.find_by_sam_account_name(entry.username)
                if obj:
                    if entry.clear_text_password is not None:
                        obj.clear_text_password = entry.clear_text_password
                    if entry.nt_hash is not None and entry.lm_hash is not None:
                        obj.nt_hash = entry.nt_hash
                        obj.lm_hash = entry.lm_hash
                else:
                    if entry.username.endswith('$'):
                        computer = Computer(
                            sam_account_name=entry.username,
                            nt_hash=entry.nt_hash,
                            lm_hash=entry.lm_hash,
                            user_with_domain=entry.sam_account_name
                        )
                        domain_state.add_computer(computer)
                    else:
                        user = User(
                            sam_account_name=entry.username,
                            nt_hash=entry.nt_hash,
                            lm_hash=entry.lm_hash,
                            user_with_domain=entry.sam_account_name
                        )
                        domain_state.add_user(user)
            except Exception as e:
                print(f"Error updating data for {entry.username}: {str(e)}") 