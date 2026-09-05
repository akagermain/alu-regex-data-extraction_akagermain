#!/usr/bin/python3

import re

email_pattern = re.compile(
        r'\b[a-zA-Z0-9](?:[a-zA-Z0-9._%+-]*[a-zA-Z0-9])?'
        r'@'
        r'[a-zA-Z0-9](?:[a-zA-Z0-9]*[a-zA-Z0-9])?'
        r'(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)+'
        r'\b'
)

# ALU specific domains that require extra validation:
alu_domain_rules = {
        'official': re.compiler(r'@alueducation\.com$', re.IGNORECASE),
        'alumni': re.compiler(r'@alumni\.alueducation\.com$', re.IGNORECASE),
        'si': re.compiler(r'@si\.alueducation\.com$', re.IGNORECASE),
}

def classify_email(email: str) -> str:
    """Return which ALU category (if any) an email belongs to."""
    for belong, pattern in alu_domain_rules.items():
        if pattern.search(email):
            return f'alu_{belong}'
    return 'external'


