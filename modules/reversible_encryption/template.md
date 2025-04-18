# Reversible Encryption Vulnerability Report

## Summary
Found {{ total_found }} accounts with reversible encryption enabled (clear text passwords).

## Vulnerable Accounts Details
| Account | Type | Status | Admin Rights | Password |
|---------|------|---------|--------------|----------|
{% for item in reversible_encryption %}| {{ item.account }} | {{ item.type }} | {% if item.is_enabled %}Enabled{% else %}Disabled{% endif %} | {% if item.is_admin %}Yes{% else %}No{% endif %} | {{ item.password }} |
{% endfor %} 