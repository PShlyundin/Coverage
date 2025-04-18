import os
import zipfile
import tempfile
import shutil
from typing import Optional, List, Set, Dict
from models.group import Group
from models.user import User
from models.computer import Computer

def extract_zip(zip_path: str, extract_dir: Optional[str] = None) -> str:
    """Extract ZIP file to temporary directory"""
    if extract_dir is None:
        extract_dir = tempfile.mkdtemp()
    
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(extract_dir)
    
    return extract_dir

def find_file_in_directory(directory: str, filename: str) -> Optional[str]:
    """Find file in directory recursively"""
    for root, _, files in os.walk(directory):
        if filename in files:
            return os.path.join(root, filename)
    return None

def list_modules() -> None:
    """List available modules"""
    print("Available modules:")
    # Look for modules in the project root directory
    modules_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'modules')
    
    if not os.path.exists(modules_path):
        print(f"Warning: Modules directory not found at {modules_path}")
        return
        
    for module in os.listdir(modules_path):
        if os.path.isdir(os.path.join(modules_path, module)) and not module.startswith('__'):
            print(f"- {module}")

def find_ldap_json(path: str) -> Optional[str]:
    """Find LDAP JSON file in directory, ZIP file or return path if it's a file"""
    ldd = []
    if os.path.isfile(path):
        if path.endswith('.zip'):
            # Extract ZIP to temporary directory
            temp_dir = extract_zip(path)
            try:
                # Look for JSON files in extracted directory
                for root, _, files in os.walk(temp_dir):
                    for file in files:
                        if file.endswith('.json'):
                            ldd.append(os.path.join(root, file))
            except Exception as e:
                print(f'Error: {e}')
            return ldd
    elif os.path.isdir(path):
        # Look for JSON files in directory
        for root, _, files in os.walk(path):
            for file in files:
                if file.endswith('.json'):
                    ldd.append(os.path.join(root, file))
        return ldd
    
    return None

def find_ntds_dit(path: str) -> Optional[str]:
    """Find NTDS.dit file in directory, ZIP file or return path if it's a file"""
    ntds = []
    if os.path.isfile(path):
        if path.endswith('.zip'):
            # Extract ZIP to temporary directory
            temp_dir = extract_zip(path)
            try:
                # Look for NTDS.dit file in extracted directory
                for root, _, files in os.walk(temp_dir):
                    for file in files:
                        if '.ntds' in file.lower():
                            ntds.append(os.path.join(root, file))
            except Exception as e:
                print(f'Error: {e}')
            return ntds
    elif os.path.isdir(path):
        # Look for NTDS.dit file in directory
        for root, _, files in os.walk(path):
            for file in files:
                if '.ntds' in file.lower():
                    ntds.append(os.path.join(root, file))
        return ntds
    
    return None

def mask_password(password: str) -> str:
    """Mask password for display in reports
    
    Args:
        password: Password to mask
        
    Returns:
        Masked password string
    """
    if not password:
        return "***"
        
    length = len(password)
    
    if length > 4:
        return f"{password[:2]}***{password[-2:]}"
    elif length > 2:
        return f"{password[0]}***{password[-1]}"
    else:
        return "***"

def get_domain_admin_recursive_groups(domain, da_groups: List[str]) -> List[str]:
    """Get SIDs of domain admin groups
    
    Args:
        domain_sid: Domain SID
        
    Returns:
        List of SIDs for Domain Admins, Administrators and Enterprise Admins groups
    """    
    # Well-known RIDs for admin groups
    da_groups = [domain.find_by_sid(e) for e in da_groups if type(e) == str]
    #recursively get all members of the groups
    for group_name, group in domain.groups.items():
        for member in group.memberof:
            if member in [group.name for group in da_groups] and not group in da_groups:
                da_groups.append(group)

    return da_groups

def cn2sam(domain, dn: str) -> str:
    """Convert CN to SAM Account Name"""
    for user in domain.users.values():
        if user.distinguished_name == dn:
            return user.sam_account_name
    return None

def get_all_group_members(domain, target_group_sids: List[str]|str) -> List[str]:
    """Recursively get all members of target groups
    
    Args:
        groups: Dictionary of all groups
        target_group_sids: List of target group SIDs to check membership for
        visited_groups: Set of already visited group SIDs to avoid cycles
        
    Returns:
        Set of member SIDs
    """
    members = []
    if isinstance(target_group_sids, str):
        target_group_sids = [target_group_sids]

    for group in target_group_sids:
        users = group.members
        for user in users:
            user = cn2sam(domain, user)
            if user not in members: 
                members.append(user)
        
    return members

def is_user_in_domain_admin_groups(sam_account_name: str, domain) -> bool:
    """Check if SID belongs to domain admin groups
    
    Args:
        sid: SID to check
        domain_sid: Domain SID
        groups: Dictionary of all groups
        
    Returns:
        True if SID belongs to domain admin groups
    """
    da_groups=[
        f"{domain.domain_sid}-512",  # Domain Admins
        f"S-1-5-32-544",  # Administrators
        f"{domain.domain_sid}-519"   # Enterprise Admins
    ]
    count_groups = 0
    while count_groups < len(da_groups):
        count_groups = len(da_groups)
        da_groups = get_domain_admin_recursive_groups(domain, da_groups)
    
    admin_members = get_all_group_members(domain, da_groups)
    return sam_account_name in admin_members