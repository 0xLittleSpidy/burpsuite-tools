#!/usr/bin/env python3
# Created with the help of an AI Agent and littlespidy.
"""
Integrate payloads from PayloadBox repositories (https://github.com/payload-box)
into Burp Suite extension payload JSON files.

- Updates existing duplicates with sourceType containing PayloadBox and adds sourceFile.
- Adds new payloads with unique IDs, descriptive names, and detailed descriptions.
- Updates http_request_smuggling_payloads.json to include sourceType and sourceFile for all entries.
"""

import os
import json
import glob
import re

def clean_lines(filepath):
    lines = []
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line_str = line.rstrip('\r\n')
            s = line_str.strip()
            if not s:
                continue
            if s.startswith(('#', '//', '/*', '*/', '*')):
                continue
            lines.append(line_str)
    return lines

def format_title_from_filename(filename):
    base = os.path.basename(filename)
    if base.endswith('.txt'):
        base = base[:-4]
    parts = re.split(r'[-_]', base)
    words = [p.capitalize() for p in parts if p]
    return ' '.join(words)

def process_smuggling_payloads():
    smug_path = 'http_request_smuggling_payloads.json'
    with open(smug_path, 'r', encoding='utf-8') as f:
        entries = json.load(f)[:40]

    # 1. Backfill sourceType and sourceFile for existing entries
    for e in entries:
        if 'sourceType' not in e or not e['sourceType']:
            desc = e.get('description', '')
            if 'OWASP' in desc:
                e['sourceType'] = 'OWASP'
                e['sourceFile'] = 'http-request-smuggling-payloads.txt'
            elif 'PayloadsAllTheThings' in desc:
                e['sourceType'] = 'PayloadsAllTheThings'
                e['sourceFile'] = 'README.md'
            else:
                e['sourceType'] = 'Manual'
                e['sourceFile'] = 'N/A'

    def norm_b(b):
        return b.replace(r'\r\n', '\n').replace('\r\n', '\n').replace('\r', '\n').strip()

    def req_sig(headers, body):
        h_norm = tuple(sorted((k.lower(), v.strip()) for k, v in headers.items()))
        b_norm = norm_b(body)
        return (h_norm, b_norm)

    sig_index = {}
    for idx, e in enumerate(entries):
        s = req_sig(e.get('headers', {}), e.get('body', ''))
        sig_index[s] = idx

    int_dir = 'payload-box/http-request-smuggling-payloads/Intruder'
    matched_count = 0
    added_count = 0

    def parse_smuggling_file(fpath):
        with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        raw_reqs = re.split(r'\n+(?=(?:POST|GET|PUT|DELETE|HEAD) \S+ HTTP/1\.[01])', content)
        parsed = []
        for raw in raw_reqs:
            raw = raw.strip()
            if not raw:
                continue
            lines = raw.splitlines()
            req_line = lines[0]
            headers = {}
            body_lines = []
            in_body = False
            for line in lines[1:]:
                if not in_body:
                    if line.strip() == '':
                        in_body = True
                        continue
                    colon = line.find(':')
                    if colon > 0:
                        k = line[:colon].strip()
                        v = line[colon+1:].strip()
                        headers[k] = v
                    else:
                        in_body = True
                        body_lines.append(line)
                else:
                    body_lines.append(line)
            body = '\\r\\n'.join(body_lines)
            parsed.append((req_line, headers, body))
        return parsed

    for fname in sorted(os.listdir(int_dir)):
        if not fname.endswith('.txt'):
            continue
        fpath = os.path.join(int_dir, fname)
        reqs = parse_smuggling_file(fpath)
        base_title = format_title_from_filename(fname)
        file_idx = 1
        for req_line, headers, body in reqs:
            s = req_sig(headers, body)
            if s in sig_index:
                e = entries[sig_index[s]]
                st_list = [x.strip() for x in e.get('sourceType', 'Manual').split(',') if x.strip()]
                if 'PayloadBox' not in st_list:
                    st_list.append('PayloadBox')
                e['sourceType'] = ', '.join(st_list)

                sf_list = [x.strip() for x in e.get('sourceFile', 'N/A').split(',') if x.strip() and x.strip() != 'N/A']
                if fname not in sf_list:
                    sf_list.append(fname)
                e['sourceFile'] = ', '.join(sf_list) if sf_list else fname
                matched_count += 1
            else:
                name = f'{base_title} #{file_idx}'
                file_idx += 1
                desc = f'HTTP Request Smuggling probe from PayloadBox ({fname}). Target request line: {req_line}'
                new_entry = {
                    'name': name,
                    'description': desc,
                    'headers': headers,
                    'body': body,
                    'sourceType': 'PayloadBox',
                    'sourceFile': fname
                }
                entries.append(new_entry)
                sig_index[s] = len(entries) - 1
                added_count += 1

    with open(smug_path, 'w', encoding='utf-8') as f:
        json.dump(entries, f, indent=2)

    print(f'[Smuggling] Total: {len(entries)}, Matched existing: {matched_count}, Added new: {added_count}')


def parse_waf_bypass_sections():
    waf_file = 'payload-box/waf-bypass-payload-list/intruder/waf_bypass_payloads.txt'
    if not os.path.exists(waf_file):
        return {}

    with open(waf_file, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()

    current_sec = 'header'
    sections = {}
    for line in lines:
        s = line.strip()
        if s.startswith('/*') and s.endswith('*/') and any(k in s for k in ['Bypass', 'Attempts', 'Injection', 'Polyglots', 'Entity', 'SSTI', 'LFI']):
            current_sec = s.replace('/*', '').replace('*/', '').strip()
            sections[current_sec] = []
            continue
        if current_sec not in sections:
            sections[current_sec] = []
        if s and not s.startswith(('#', '//', '/*', '*/', '*')):
            sections[current_sec].append(line.rstrip('\r\n'))

    return sections


def process_parameter_payloads():
    waf_sections = parse_waf_bypass_sections()

    categories = [
        {
            'json_file': 'business_logic_payloads_littlespidy.json',
            'prefix': 'business-logic-pbox',
            'display': 'Business Logic',
            'files': ['payload-box/business-logic-exploitation-playbook/Intruder/business-logic-payloads.txt'],
            'extra_items': []
        },
        {
            'json_file': 'command_injection_payloads_littlespidy.json',
            'prefix': 'command-injection-pbox',
            'display': 'Command Injection',
            'files': sorted(glob.glob('payload-box/command-injection-payload-list/Intruder/*.txt')) + [
                'payload-box/protocol-injection-payload-list/Intruder/command-injection.txt'
            ],
            'extra_items': [('waf_bypass_payloads.txt', p) for p in waf_sections.get('Command Injection / RCE Bypasses', [])]
        },
        {
            'json_file': 'crlf_injection_payloads_littlespidy.json',
            'prefix': 'crlf-pbox',
            'display': 'CRLF Injection',
            'files': [
                'payload-box/crlf-injection-payload-list/Intruder/crlf-injection.txt',
                'payload-box/protocol-injection-payload-list/Intruder/smtp-injection.txt',
                'payload-box/protocol-injection-payload-list/Intruder/http-injection.txt'
            ],
            'extra_items': []
        },
        {
            'json_file': 'csv_injection_payloads_littlespidy.json',
            'prefix': 'csv-injection-pbox',
            'display': 'CSV Injection',
            'files': ['payload-box/csv-injection-payload-list/Intruder/csv-injection-intruder.txt'],
            'extra_items': []
        },
        {
            'json_file': 'path_traversal_payloads_littlespidy.json',
            'prefix': 'path-traversal-pbox',
            'display': 'Path Traversal',
            'files': ['payload-box/directory-payload-list/Intruder/special-encoded.txt'],
            'extra_items': []
        },
        {
            'json_file': 'security_misconfiguration_payloads_littlespidy.json',
            'prefix': 'security-misconfiguration-pbox',
            'display': 'Security Misconfiguration',
            'files': [f for f in sorted(glob.glob('payload-box/directory-payload-list/Intruder/*.txt')) if not f.endswith('special-encoded.txt')],
            'extra_items': [('waf_bypass_payloads.txt', p) for p in waf_sections.get('Generic Long Strings / Overflow Attempts', [])]
        },
        {
            'json_file': 'open_redirect_payloads_littlespidy.json',
            'prefix': 'open-redirect-pbox',
            'display': 'Open Redirect',
            'files': [
                'payload-box/open-redirect-payload-list/payloads.txt',
                'payload-box/open-redirect-payload-list/payloads/01-protocol-based.txt',
                'payload-box/open-redirect-payload-list/payloads/02-encoding-variations.txt'
            ],
            'extra_items': []
        },
        {
            'json_file': 'ssrf_payloads_littlespidy.json',
            'prefix': 'ssrf-pbox',
            'display': 'SSRF',
            'files': ['payload-box/protocol-injection-payload-list/Intruder/ssrf-injection.txt'],
            'extra_items': []
        },
        {
            'json_file': 'ldap_injection_payloads_littlespidy.json',
            'prefix': 'ldap-injection-pbox',
            'display': 'LDAP Injection',
            'files': ['payload-box/protocol-injection-payload-list/Intruder/ldap-injection.txt'],
            'extra_items': []
        },
        {
            'json_file': 'xml_injection_payloads_littlespidy.json',
            'prefix': 'xml-injection-pbox',
            'display': 'XML Injection',
            'files': ['payload-box/protocol-injection-payload-list/Intruder/xpath-injection.txt'],
            'extra_items': []
        },
        {
            'json_file': 'sql_payloads.json',
            'prefix': 'sqli-pbox',
            'display': 'SQL Injection',
            'files': sorted(glob.glob('payload-box/sql-injection-payload-list/*.txt')) + [
                'payload-box/protocol-injection-payload-list/Intruder/sql-injection.txt'
            ],
            'extra_items': [('waf_bypass_payloads.txt', p) for p in waf_sections.get('SQL Injection WAF Bypasses', [])]
        },
        {
            'json_file': 'csti_payloads.json',
            'prefix': 'csti-pbox',
            'display': 'CSTI',
            'files': sorted(glob.glob('payload-box/ssti-advanced-payload-list/Intruder/*.txt')),
            'extra_items': [('waf_bypass_payloads.txt', p) for p in waf_sections.get('Server Side Template Injection (SSTI)', [])]
        },
        {
            'json_file': 'file_inclusion_payloads_littlespidy.json',
            'prefix': 'lfi-pbox',
            'display': 'File Inclusion',
            'files': [],
            'extra_items': [('waf_bypass_payloads.txt', p) for p in waf_sections.get('Local File Inclusion (LFI) Bypasses', [])]
        },
        {
            'json_file': 'xxe_injection_payloads_littlespidy.json',
            'prefix': 'xxe-pbox',
            'display': 'XXE Injection',
            'files': sorted(glob.glob('payload-box/xxe-injection-payload-list/Intruder/*.txt')) + [
                'payload-box/protocol-injection-payload-list/Intruder/xxe-injection.txt'
            ],
            'extra_items': [('waf_bypass_payloads.txt', p) for p in waf_sections.get('XML External Entity (XXE)', [])]
        },
        {
            'json_file': 'xss_payloads.json',
            'prefix': 'xss-pbox',
            'display': 'XSS',
            'files': sorted(glob.glob('payload-box/xss-payload-list/Payloads/**/*.txt', recursive=True)),
            'extra_items': [('waf_bypass_payloads.txt', p) for p in waf_sections.get('XSS WAF Bypasses', [])] +
                           [('waf_bypass_payloads.txt', p) for p in waf_sections.get('Polyglots (Mixed Contexts)', [])]
        }
    ]

    for cat in categories:
        json_file = cat['json_file']
        prefix = cat['prefix']
        display = cat['display']

        if not os.path.exists(json_file):
            print(f'Warning: {json_file} does not exist, skipping.')
            continue

        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # Ensure sourceType and sourceFile for all existing entries
        for e in data:
            if 'sourceType' not in e or not e['sourceType']:
                e['sourceType'] = 'Manual'
            if 'sourceFile' not in e or not e['sourceFile']:
                e['sourceFile'] = 'N/A'

        existing_by_template = {}
        for e in data:
            tpl = e.get('template', '')
            if tpl:
                existing_by_template[tpl] = e
                existing_by_template[tpl.strip()] = e

        id_counter = 1
        matched_count = 0
        added_count = 0

        # Process standard files
        for fpath in cat['files']:
            if not os.path.exists(fpath):
                continue
            src_fname = os.path.basename(fpath)
            title_base = format_title_from_filename(src_fname)
            file_item_idx = 1
            payload_lines = clean_lines(fpath)
            for raw_line in payload_lines:
                norm_key = raw_line.strip()
                if not norm_key:
                    continue

                if norm_key in existing_by_template:
                    e = existing_by_template[norm_key]
                    st_list = [x.strip() for x in e.get('sourceType', 'Manual').split(',') if x.strip()]
                    if 'PayloadBox' not in st_list:
                        st_list.append('PayloadBox')
                    e['sourceType'] = ', '.join(st_list)

                    sf_list = [x.strip() for x in e.get('sourceFile', 'N/A').split(',') if x.strip() and x.strip() != 'N/A']
                    if src_fname not in sf_list:
                        sf_list.append(src_fname)
                    e['sourceFile'] = ', '.join(sf_list) if sf_list else src_fname
                    matched_count += 1
                else:
                    new_id = f'{prefix}-{id_counter:04d}'
                    id_counter += 1
                    name = f'{title_base} #{file_item_idx}'
                    file_item_idx += 1
                    t_snippet = raw_line if len(raw_line) <= 60 else raw_line[:60] + '...'
                    desc = f'{display} probe from PayloadBox ({src_fname}). Tests application handling of: {t_snippet}'
                    new_entry = {
                        'id': new_id,
                        'name': name,
                        'template': raw_line,
                        'description': desc,
                        'enabled': True,
                        'sourceType': 'PayloadBox',
                        'sourceFile': src_fname
                    }
                    data.append(new_entry)
                    existing_by_template[raw_line] = new_entry
                    existing_by_template[norm_key] = new_entry
                    added_count += 1

        # Process extra items (e.g. from WAF bypass sections)
        extra_item_idx = 1
        for src_fname, raw_line in cat['extra_items']:
            norm_key = raw_line.strip()
            if not norm_key:
                continue

            if norm_key in existing_by_template:
                e = existing_by_template[norm_key]
                st_list = [x.strip() for x in e.get('sourceType', 'Manual').split(',') if x.strip()]
                if 'PayloadBox' not in st_list:
                    st_list.append('PayloadBox')
                e['sourceType'] = ', '.join(st_list)

                sf_list = [x.strip() for x in e.get('sourceFile', 'N/A').split(',') if x.strip() and x.strip() != 'N/A']
                if src_fname not in sf_list:
                    sf_list.append(src_fname)
                e['sourceFile'] = ', '.join(sf_list) if sf_list else src_fname
                matched_count += 1
            else:
                new_id = f'{prefix}-{id_counter:04d}'
                id_counter += 1
                name = f'WAF Bypass #{extra_item_idx}'
                extra_item_idx += 1
                t_snippet = raw_line if len(raw_line) <= 60 else raw_line[:60] + '...'
                desc = f'{display} probe from PayloadBox ({src_fname}). Tests application handling of: {t_snippet}'
                new_entry = {
                    'id': new_id,
                    'name': name,
                    'template': raw_line,
                    'description': desc,
                    'enabled': True,
                    'sourceType': 'PayloadBox',
                    'sourceFile': src_fname
                }
                data.append(new_entry)
                existing_by_template[raw_line] = new_entry
                existing_by_template[norm_key] = new_entry
                added_count += 1

        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)

        print(f'[{display}] File: {json_file} | Total: {len(data)}, Matched: {matched_count}, Added: {added_count}')


if __name__ == '__main__':
    print('Starting PayloadBox integration...')
    process_smuggling_payloads()
    process_parameter_payloads()
    print('Completed PayloadBox integration successfully.')
