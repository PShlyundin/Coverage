# Kerberoasting Vulnerability Report

## Summary
Found {{ total_found }} users with SPN and cracked passwords.

## Vulnerable Users
| Username | SPN | Password | Domain Admin |
|----------|-----|----------|--------------|
{% for user in vulnerable_users %}
| {{ user.username }} | {{ user.spn }} | {{ user.password }} | {{ "Yes" if user.is_domain_admin else "No" }} |
{% endfor %} 