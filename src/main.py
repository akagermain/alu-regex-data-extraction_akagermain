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



#---------------------------------------------------------------
# 2. CREDIT CARD NUMBER VALIDATION
#---------------------------------------------------------------



card_number_pattern = re.compile(r'\b(?:\d[ -]?){13,19}\b')

def luhn_is_valid(digits: str) -> bool:
    """Standard Luhn checksum used by all major card networks."""
    total = 0
    reverse_digits = digits[::-1]
    for i, ch in enumerate(reverse_digits):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def find_card_candidate_spans(text: str):
    """All spans that structurally look like a card number, valid or not.
    We will use this later to stop the phone extractor from re-claiming 
    these digits."""
    return [m.span() for m in card_number_pattern.finditer(text)]


def extract_credit_cards(text: str):
    results = []
    for match in card_number_pattern.finditer(text):
        raw = match.group()
        digits = re.sub(r'[ -]', '', raw)
        # Valid card lengths: Visa/MasterCard/Discover = 16, Amex = 15, some = 13/19
        if len(digits) in (13, 15, 16, 19) and luhn_is_valid(digits):
            results.append(digits)
    return results


def mask_card(digits: str) -> str:
    """Mask all except the last 4 digits, PCI-style."""
    return digits[:4] + '*' * (len(digits) - 8) + digits[-4:]



#---------------------------------------------------------------
# 3. URLs
#---------------------------------------------------------------


"""Only http/https are considered safe to extract. other schemes 
(ftp://, file://, data:) are explicitly excluded from the pattern 
itself - security by construction rather than a denylist filter 
applied after the fact."""


url_pattern = re.compile(
        r'\bhttps?://'              # required safe scheme
        r'[a-zA-Z0-9.-]+'           # domain
        r'(?:\.[a-zA-Z]{2,})'       # Top level domain
        r'(?::\d+)?'                # optional port
        r'(?:/[^\s<>"\']*)?'        # optional path/query, stop at whitespace/quotes
)



#---------------------------------------------------------------
# 4. PHONE NUMBER
#---------------------------------------------------------------


phone_pattern = re.compile(
        r'(?:\+\d{1,3}[\s.-]?)?'           # optional country code
        r'(?:\(\d{2,4}\)[\s.-]?)?'         # optional area code
        r'\d{2,4}(?:[\s.-]\d{2,4}){1,4}'   # 2-5 digit group joined by separators
)


def extract_phone_numbers(text: str, card_spans) -> list:
    
    results = []
    for match in phone_pattern.finditer(text):
        start, end =match.span()
        if any(start < c_end and end > c_start for c_start, c_end in card_spans):
            continue

        raw = match.group().strip()
        digit_count = len(re.sub(r'\D', '', raw))
        if 7 <= digit_count <= 15:
            results.append(raw)
    return results


def mask_phone(phone: str) -> str:
    digits_only = re.sub(r'\D', '', phone)
    middle_len = max(len(digits_only) - 6, 0)
    return digits_only[:3] + '*' * middle_len + digits_only[-3:]



#---------------------------------------------------------------
# Temporary quick test block
#---------------------------------------------------------------



if __name__ == '__main__':
    with open('/home/germain/ALU/alu-regex-data-extraction_akagermain/input/raw-text.txt', 'r', encoding='utf-8') as file:
        text = file.read()

    emails = email_pattern.findall(text)
    print(f"Found {len(emails)} email(s): ")
    for e in emails:
        print(f" - {mask_email(e)} [{classify_email(e)}]")


    cards = extract_credit_cards(text)
    print(f"\nFound {len(cards)} valid credit card(s): ")
    for c in cards:
        print(f" - {mask_card(c)}")

    urls = url_pattern.findall(text)
    print(f"\nFound {len(urls)} URL(s): ")
    for u in urls:
        print(f" - {u}")

    card_spans = find_card_candidate_spans(text)
    phones = extract_phone_numbers(text, card_spans)
    print(f"\nFound {len(phones)} phone number(s): ")
    for p in phones:
        print(f" - {mask_phone(p)}")









