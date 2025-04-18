# Passwords in Description Vulnerability Report

## Summary
Found {{ total_found }} accounts with passwords found in their descriptions.

## Vulnerable Accounts Details
| Account | Status | Admin Rights | Password | Description |
|---------|---------|--------------|----------|----------|
{% for item in passwords_in_description %}| {{ item.account }} | {% if item.is_enabled %}Enabled{% else %}Disabled{% endif %} | {% if item.is_admin %}Yes{% else %}No{% endif %} | {{ item.password }} | {{ item.description }}
{% endfor %} 