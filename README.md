# Data Extraction and Secure Validation Assignment

This is a regex-based python program that extracts and validates four structured data types from raw, messy, production-style text (email addresses, credit card numbers, URLs, and phone numbers)

## How to run

```bash
python3 src/main.py
```

The script reads 'input/raw-text.txt', extracts and validates all data types, prints a masked console summary, and writes the full structured results to 'output/sample-output.json'.

No external dependencies are required (standard library only: 're', 'json', 'os').

## Data Types and Regex logic:

### 1. Email addresses
Matches `local-part@domain.tld` shapes. Deliberately rejects obfuscated or malformed attempts commonly seen in scraped/real-world text, such as `user[at]domain(dot)com`, double '@@', and missing domains - these simply don't match the pattern's structure.

**ALU-specific validation:** every matched email is additionally checked against three domain rules and tagged accordingly:
- `@alueducation.com` -> `alu_official`
- `@alumni.alueducation.com` -> `alu_alumni`
- `@si.alueducation.com` -> `alu_si`
- anything else -> `external`

### 2. Credit card Numbers
Digits are often grouped with spaces or dashes in real text. The regex first finds any 13-19 digit run allowing single space or dash separators, then the separator are stripped and the result is verified with a **Luhn checksum** - the same algorithm real payment systems use. A number that merely "looks like" a card but fails Luhn (or is the wrong length) is discarded, not reported as valid.

### 3. URLs
only `http://` and `https://` schemes are matched. This is enforced by the pattern itself, not a filter applied afterward. Unsafe schemes such as (ftp://, file://) cannot match, so they are never extracted.

### 4. Phone Numbers
Covers international (`+250 788 123 456`), local dashed (`078-234-5678`), and paranthesised-area-code (`+1 (123) 456-7890`) formats. Numbers are validated by counting digits (7-15) and requiring at least two separated digit groups, so stray unformatted numbers aren't mistaken for phone numbers. Numbers that overlap a credit-card-shaped sequence are skipped, so a card fragment is never double-counted as a phone number.

**Note:** a short pair like '4111 1111' (used in the sample input to simulate a truncated/invalid card) is structually indistinguishable from valid short local phone format used in some regions, so it is reported as a phone number.


## Security Consideration

- **No blind trust of input:** every extracted value is structurally and/or checksum-validated before being treated as "real" data.
- **Injection-style content is never treated as valid data.** Regex are anchored to speicif formats, so `<script>` tags, SQL fragments, and shell metacharacters cannot match any extraction pattern.
`flag_hostile_lines()` separately scans for these patterns and reports them as security flags, without ever extracting them as data.
- **Sensitive data is not exposed unnecessarily.** The console summary only prints masked emails, card numbers, and phone numbers. Full unmasked values are written only to the structured json output file.
- **Unsafe URL schemes are rejected by construction**, not by denylist.

## Repository structure

`
alu-regex-data-extraction_akagermain/
|-- input/
|   '-- raw-text.txt        # sample input (valid + hostile/invalid cases)
|-- src/
|   '-- main.py             # Extraction, validation, and security logic
|-- output/
|   '-- sample-output.json  # Generated structured results  
'-- README.md
`

