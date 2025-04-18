# AS-REP Roasting Vulnerability Report

## Summary
Found {{ total_found }} users vulnerable to AS-REP Roasting (DONT_REQUIRE_PREAUTH enabled).

## Vulnerable Users
| Username | Password | Status |
|----------|----------|--------|
{% for user in all_users %}| {{ user.username }} | {{ user.password }} | {{ "Enable" if user.enable else "Disable" }} |
{% endfor %} 