from typing import Dict, Any, List, Tuple, Optional
from dataclasses import dataclass
from core.interfaces import IParser
from core.domain_state import DomainState
from core.exceptions import ValidationError

@dataclass
class HashcatEntry:
    """Data class for Hashcat entries"""
    nt_hash: str
    password: str

class HashcatParser(IParser):
    """Parser for Hashcat output files"""
    def __init__(self, output_path: str):
        self.output_path = output_path
        self.data: List[HashcatEntry] = []

    def load_data(self) -> None:
        """Load Hashcat data from file"""
        try:
            with open(self.output_path, 'r') as f:
                for line in f:
                    entry = self._parse_line(line)
                    if entry:
                        self.data.append(entry)
        except Exception as e:
            raise ValidationError(f"Failed to load Hashcat data: {str(e)}")

    def _parse_line(self, line: str) -> Optional[HashcatEntry]:
        """Parse single line from Hashcat output
        
        Expected format: hash:password
        Example: 31d6cfe0d16ae931b73c59d7e0c089c0:password123
        Example with colon in password: 31d6cfe0d16ae931b73c59d7e0c089c0:P@ssw0rd12:345
        """
        try:
            line = line.strip()
            if not line:
                return None

            # Split by first colon only to handle passwords with colons
            parts = line.split(':', 1)
            if len(parts) != 2:
                return None

            nt_hash, password = parts
            if len(nt_hash) != 32:
                return None

            return HashcatEntry(nt_hash=nt_hash, password=password)
        except Exception:
            return None

    def validate_format(self) -> bool:
        """Validate Hashcat output format"""
        try:
            self.load_data()
            if not self.data:
                print("Warning: No valid entries found in Hashcat output")
                return False
            
            return True
        except Exception as e:
            print(f"Invalid Hashcat output format: {str(e)}")
            return False

    def parse(self, domain_state: DomainState) -> None:
        """Parse Hashcat output and update domain state"""
        for entry in self.data:
            try:
                domain_state.update_user_password(entry.nt_hash, entry.password)
            except Exception as e:
                print(f"Error updating password for hash {entry.nt_hash}: {str(e)}") 