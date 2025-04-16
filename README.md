# Domain Coverage Analysis Tool

Tool for analyzing domain security based on various data sources:
- LDAP domain dump
- NTDS.dit dump
- Hashcat output

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
python src/main.py --ldap <path_to_ldap_dump> --ntds <path_to_ntds_dump> --hashcat <path_to_hashcat_output> --output <output_file>
```

## Module Development

To create a new module:

1. Create a new directory in `src/modules/`
2. Create `module.py` implementing `IModule` interface
3. Create `template.md` with Jinja2 template for report

Example module structure:
```
src/modules/my_module/
├── module.py
└── template.md
``` 