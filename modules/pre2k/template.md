# Pre-2000 Compatibility Vulnerability Report

## Summary
Found {{ total_found }} users with Pre-2000 compatibility enabled.

## Vulnerable Computers
| Computer | Password | Status |
|----------|----------|--------|
{% for computer in all_users %}| {{ computer.username }} | {{ computer.password }} | {{ "Enable" if computer.status else "Disable" }} |
{% endfor %} 