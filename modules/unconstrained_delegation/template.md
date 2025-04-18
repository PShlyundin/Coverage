# Unconstrained Delegation Vulnerability Report

## Summary
Found {{ total_found }} accounts with unconstrained delegation enabled.

## Vulnerable Accounts Details
| Account | Type | Status |
|---------|------|---------|
{% for item in unconstrained_delegation %}| {{ item.account }} | {{ item.type }} | {% if item.is_enabled %}Enabled{% else %}Disabled{% endif %} |
{% endfor %} 