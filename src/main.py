#!/usr/bin/python3

import re

#---------------------------------------------------------------
# 1. EMAIl VALIDATION
#---------------------------------------------------------------

email_pattern = re.compile(
        r'\b[a-zA-Z0-9](?:[a-zA-Z0-9._%+-]*[a-zA-Z0-9])?'
        r'@'
        r'[a-zA-Z0-9](?:[a-zA-Z0-9]*[a-zA-Z0-9])?'
        r'(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)+'
        r'\b'
)

# ALU specific domains that require extra validation:
alu_domain_rules = {
        'official': re.compile(r'@alueducation\.com$', re.IGNORECASE),
        'alumni': re.compile(r'@alumni\.alueducation\.com$', re.IGNORECASE),
        'si': re.compile(r'@si\.alueducation\.com$', re.IGNORECASE),
}


def classify_email(email: str) -> str:
    """Return which ALU category (if any) an email belongs to."""
    for belong, pattern in alu_domain_rules.items():
        if pattern.search(email):
            return f'alu_{belong}'
    return 'external'


def mask_email(email: str) ->str:
    """Mask an email for safe display (eg; ju****@alueducation.com)."""
    local, _, domain = email.partition('@')
    if len(local) <= 2:
        masked_local = local[0] + '*'
    else:
        masked_local = local[:2] + '*' * (len(local) - 2)
    return f'{masked_local}@{domain}'


if __name__ == '__main__':
    with open('/home/germain/ALU/alu-regex-data-extraction_akagermain/input/raw-text.txt', 'r', encoding='utf-8') as file:
        text = file.read()

    emails = email_pattern.findall(text)
    print(f"Found {len(emails)} email(s): ")
    for e in emails:
        print(f" - {mask_email(e)} [{classify_email(e)}]")
