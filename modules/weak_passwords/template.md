# Weak Passwords Vulnerability Report

## Summary
Found {{ total_found }} users with weak passwords.

## Users with Weak Passwords
| Username | Password | Domain Admin | Status |
|----------|----------|--------------|--------|
{% for user in weak_password_users %}| {{ user.username }} | {{ user.password }} | {{ "Yes" if user.is_domain_admin else "No" }} | {{ "Active" if user.enabled else "Disabled" }} |
{% endfor %}