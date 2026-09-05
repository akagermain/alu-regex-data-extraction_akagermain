#!/usr/bin/python3

import re

email_pattern = re.compile(
        r'\b[a-zA-Z0-9](?:[a-zA-Z0-9._%+-]*[a-zA-Z0-9])?'
        r'@'
        r'[a-zA-Z0-9](?:[a-zA-Z0-9]*[a-zA-Z0-9])?'
        r'(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)+'
        r'\b'
)

alu_domain_rules = {
        'official': re.compiler(r'@alueducation\.com$', re.IGNORECASE),
        'alumni': re.compiler(r'@alumni\.alueducation\.com$', re.IGNORECASE),
        'si': re.compiler(r'@si\.alueducation\.com$', re.IGNORECASE),
}


