import json
from typing import Dict, Any, List, Optional
from core.interfaces import IParser
from core.domain_state import DomainState
from models.user import User
from models.group import Group
from models.computer import Computer
from core.exceptions import ValidationError

class BaseLdapParser:
    """Base class for LDAP data parsers"""
    def __init__(self, json_path: str):
        self.json_path = json_path
        self.data: List[Dict[str, Any]] = []

    def load_data(self) -> None:
        """Load JSON data from file"""
        try:
            with open(self.json_path, 'r') as f:
                self.data = json.load(f)
        except Exception as e:
            raise ValidationError(f"Failed to load JSON data: {str(e)}")

    def get_attribute(self, obj: Dict[str, Any], key: str, default=None, is_list: bool = False) -> Any:
        """Get attribute value from LDAP object"""
        value = obj.get('attributes', {}).get(key, default)
        if is_list:
            return value if isinstance(value, list) else []
        return value[0] if isinstance(value, list) and value else value

    def validate_format(self) -> bool:
        """Template method for format validation"""
        try:
            self.load_data()
            return True
        except Exception as e:
            print(f"Invalid JSON format: {str(e)}")
            return False

    def __str__(self) -> str:
        return f"BaseLdapParser: {self.json_path}"
    
    def CN2name(self, cn: str) -> str:
        """Convert CN to name"""
        return cn.split(',')[0].split('=')[1]

class UserParser(BaseLdapParser):
    """Parser for domain_users.json"""
    def parse(self, domain_state: DomainState) -> None:
        """Parse user data and update domain state"""
        for user_data in self.data:
            try:
                user_account_control=self.get_attribute(user_data, 'userAccountControl', 0)
                user = User(
                    sam_account_name=self.get_attribute(user_data, 'sAMAccountName', ''),
                    distinguished_name=self.get_attribute(user_data, 'distinguishedName', ''),
                    spn_list=self.get_attribute(user_data, 'servicePrincipalName', [], is_list=True),
                    object_sid=self.get_attribute(user_data, 'objectSid', ''),
                    memberof=[self.CN2name(e) for e in self.get_attribute(user_data, 'memberOf', [], is_list=True)],
                    user_account_control=self.get_attribute(user_data, 'userAccountControl', 0),
                    enabled=not bool(user_account_control & 0x2),
                    description=self.get_attribute(user_data, 'description', ''),
                    members=self.get_attribute(user_data, 'member', [], is_list=True)
                )
                domain_state.add_user(user)
            except Exception as e:
                print(f"Error parsing user {self.get_attribute(user_data, 'sAMAccountName', 'unknown')}: {str(e)}")

class GroupParser(BaseLdapParser):
    """Parser for domain_groups.json"""
    def parse(self, domain_state: DomainState) -> None:
        """Parse group data and update domain state"""
        for group_data in self.data:
            try:
                group = Group(
                    name=self.get_attribute(group_data, 'name', ''),
                    sid=self.get_attribute(group_data, 'objectSid', ''),
                    memberof=[self.CN2name(e) for e in self.get_attribute(group_data, 'memberOf', [], is_list=True)],
                    members=self.get_attribute(group_data, 'member', [], is_list=True)
                )
                domain_state.add_group(group)
            except Exception as e:
                print(f"Error parsing group {self.get_attribute(group_data, 'name', 'unknown')}: {str(e)}")

class ComputerParser(BaseLdapParser):
    """Parser for domain_computers.json"""
    def parse(self, domain_state: DomainState) -> None:
        """Parse computer data and update domain state"""
        for computer_data in self.data:
            try:
                computer = Computer(
                    sam_account_name=self.get_attribute(computer_data, 'sAMAccountName', ''),
                    distinguished_name=self.get_attribute(computer_data, 'distinguishedName', ''),
                    spn_list=self.get_attribute(computer_data, 'servicePrincipalName', [], is_list=True),
                    object_sid=self.get_attribute(computer_data, 'objectSid', ''),
                    memberof=[self.CN2name(e) for e in self.get_attribute(computer_data, 'memberOf', [], is_list=True)],
                    user_account_control=self.get_attribute(computer_data, 'userAccountControl', 0),
                    description=self.get_attribute(computer_data, 'description', ''),
                    members=self.get_attribute(computer_data, 'member', [], is_list=True)
                )
                domain_state.add_computer(computer)
            except Exception as e:
                print(f"Error parsing computer {self.get_attribute(computer_data, 'sAMAccountName', 'unknown')}: {str(e)}")

class LdapParser(IParser):
    """Main LDAP parser that coordinates parsing of all LDAP data files"""
    def __init__(self, json_files: List[str]):
        self.json_files = json_files
        self.parsers: Dict[str, BaseLdapParser] = {}

    def _get_parser_for_file(self, file_path: str) -> Optional[BaseLdapParser]:
        """Get appropriate parser for file based on its name"""
        filename = file_path.lower()
        if 'users' in filename:
            return UserParser(file_path)
        elif 'groups' in filename:
            return GroupParser(file_path)
        elif 'computers' in filename:
            return ComputerParser(file_path)
        return None

    def validate_format(self) -> bool:
        """Validate format of all LDAP JSON files"""
        try:
            for file_path in self.json_files:
                parser = self._get_parser_for_file(file_path)
                if parser is None:
                    continue
                
                if not parser.validate_format():
                    print(f"Warning: Invalid format in {file_path}")
                    return False
                
                self.parsers[file_path] = parser
            
            return True
        except Exception as e:
            print(f"Error validating LDAP data: {str(e)}")
            return False

    def parse(self, domain_state: DomainState) -> None:
        """Parse all LDAP data files and update domain state"""
        for file_path, parser in self.parsers.items():
            try:
                parser.parse(domain_state)
            except Exception as e:
                print(f"Error parsing {file_path}: {str(e)}") 