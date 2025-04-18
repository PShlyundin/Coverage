# Password Reuse Vulnerability Report

## Summary
Found {{ total_found }} instances of password reuse with administrative accounts.

## Password Reuse Details
| Admin Account | Reuse Accounts | Password |
|---------------|----------------|----------|
{% for item in password_reuse %}| {{ item.admin_account }} | {% for acc in item.reuse_accounts %}{{ acc }}<br>{% endfor %} | {{ item.password }} |
{% endfor %} 