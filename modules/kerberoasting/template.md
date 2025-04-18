# Kerberoasting Vulnerability Report

## Summary
Found {{ total_found }} users with SPN and cracked passwords.

## Vulnerable Users
| Username | SPN | Password | Domain Admin |
|----------|-----|----------|--------------|
{% for user in all_users %}| {{ user.username }} | {% for spn in user.spn %}{{ spn }}  {% endfor %} | {{ user.password }} | {{ "Yes" if user.is_domain_admin else "No" }} |
{% endfor %} 