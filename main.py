#!/usr/bin/env python3
import argparse
import os
import sys
from typing import List, Optional

from core.domain_state import DomainState
from parsers.ldap_parser import LdapParser
from parsers.secrets_parser import SecretsParser
from parsers.hashcat_parser import HashcatParser
from module_system.module_loader import ModuleLoader
from module_system.module_runner import ModuleRunner
from module_system.report_builder import ReportBuilder
from core.utils import list_modules, find_ldap_json, find_ntds_dit

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='Domain Coverage Analysis Tool')
    
    # Add list-modules flag
    parser.add_argument('-l', '--list-modules', action='store_true', help='List available modules')
    
    # Add required arguments
    parser.add_argument('--ldd', help='Path to LDAP domain dump (JSON file, directory with JSON files, or ZIP archive)')
    parser.add_argument('--ntds', help='Path to NTDS.dit dump')
    parser.add_argument('--hashcat', help='Path to Hashcat output')
    
    # Optional arguments
    parser.add_argument('-o', '--output', help='Path to output report file')
    parser.add_argument('-m', '--modules', help='Comma-separated list of modules to run (default: all)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    
    args = parser.parse_args()
    
    # If not listing modules, ensure required arguments are provided
    if not args.list_modules:
        if not all([args.ldd]):
            parser.error("--ldd, --ntds, and --hashcat are required")
    
    return args

def setup_logging(debug: bool):
    """Setup logging based on debug flag"""
    import logging
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

def main():
    """Main entry point"""
    args = parse_arguments()
    if args.list_modules:
        list_modules()
        return
    
    setup_logging(args.verbose)
    
    # Initialize domain state
    domain_state = DomainState()
    
    # Parse LDAP data
    ldap_files = find_ldap_json(args.ldd)
    if not ldap_files:
        print(f"Error: Could not find any LDAP JSON files in {args.ldd}")
        sys.exit(1)
    
    ldap_parser = LdapParser(ldap_files)
    if not ldap_parser.validate_format():
        print("Error: Invalid LDAP data format")
        sys.exit(1)
    
    print("Parsing LDAP data...")
    ldap_parser.parse(domain_state)
    
    # Parse NTDS data
    ntds_files = find_ntds_dit(args.ntds)
    secrets_parser = SecretsParser(ntds_files)
    if not secrets_parser.validate_format():
        print("Error: Invalid NTDS data format")
        sys.exit(1)
    
    print("Parsing NTDS data...")
    secrets_parser.parse(domain_state)
    
    # Parse Hashcat output
    hashcat_parser = HashcatParser(args.hashcat)
    if not hashcat_parser.validate_format():
        print("Error: Invalid Hashcat output format")
        sys.exit(1)
    
    print("Parsing Hashcat output...")
    hashcat_parser.parse(domain_state)
    
    # Load modules
    module_loader = ModuleLoader(os.path.join(os.path.dirname(__file__), 'modules'))
    
    if args.modules:
        module_names = [name.strip() for name in args.modules.split(',')]
        modules = module_loader.load_specific_modules(module_names)
    else:
        modules = module_loader.load_modules()
    
    if not modules:
        print("Error: No modules found")
        sys.exit(1)
    
    print(f"Loaded {len(modules)} modules")
    
    # Run modules
    module_runner = ModuleRunner(domain_state)
    print("Running modules...")
    results = module_runner.run_modules(modules)

    # Build report
    output_path = args.output or 'report.md'
    report_builder = ReportBuilder(output_path)
    print(f"Building report to {output_path}...")
    report_builder.build_report(results)
    
    print("Done!")

if __name__ == "__main__":
    main() 