#!/usr/bin/env python3
"""Run a bounded Apify audit and apply an absolute response-header policy."""
import argparse
import json
import os
from pathlib import Path
import re
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

import yaml

GRADES = {grade: rank for rank, grade in enumerate(['F', 'D', 'C', 'B', 'A'])}
HEADERS = {'strict-transport-security', 'content-security-policy', 'x-frame-options',
           'x-content-type-options', 'referrer-policy', 'permissions-policy'}


def load_config(path):
    config = yaml.safe_load(Path(path).read_text())
    if not isinstance(config, dict) or set(config) - {'urls', 'minimum_grade', 'required_headers'}:
        raise ValueError('Config must contain urls, minimum_grade and required_headers only')
    urls = config.get('urls')
    if not isinstance(urls, list) or not 1 <= len(urls) <= 5:
        raise ValueError('Configure 1-5 public root URLs')
    origins = set()
    for url in urls:
        if not isinstance(url, str):
            raise ValueError('Every URL must be a string')
        parsed = urlsplit(url if '://' in url else 'https://' + url)
        if (parsed.scheme not in {'https', 'http'} or not parsed.hostname or
                '.' not in parsed.hostname or parsed.username or parsed.password or
                parsed.port or parsed.path not in {'', '/'} or parsed.query or parsed.fragment):
            raise ValueError('Use public http(s) root URLs without credentials, ports or query strings')
        origin = (parsed.scheme, parsed.hostname.lower())
        if origin in origins:
            raise ValueError('Duplicate URL origin')
        origins.add(origin)
    minimum = config.get('minimum_grade', 'B')
    required = config.get('required_headers', [])
    if not isinstance(minimum, str) or minimum not in GRADES:
        raise ValueError('minimum_grade must be A, B, C, D or F')
    if not isinstance(required, list) or any(not isinstance(h, str) or h.lower() not in HEADERS for h in required):
        raise ValueError('required_headers must be a list of supported header names')
    return urls, minimum, list(dict.fromkeys(h.lower() for h in required))


def run_audit(urls, token, api_base):
    parsed = urlsplit(api_base)
    if api_base != 'https://api.apify.com/v2':
        if not (parsed.scheme == 'http' and parsed.hostname in {'127.0.0.1', 'localhost'}):
            raise ValueError('API override is allowed only for loopback mock tests')
    endpoint = api_base.rstrip('/') + '/acts/hiver~website-security-headers-audit/run-sync-get-dataset-items?timeout=120&memory=256&maxTotalChargeUsd=0.05&format=json'
    request = Request(endpoint, data=json.dumps({'urls': urls, 'maxConcurrency': 5, 'timeoutSecs': 15}).encode(),
                      headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'}, method='POST')
    # Never retry this POST automatically: a timed-out run may still incur charges.
    try:
        with urlopen(request, timeout=140) as response:
            rows = json.load(response)
    except HTTPError as exc:
        raise ValueError(f'Apify API HTTP {exc.code}; check token, access and credit; no automatic retry') from None
    except (URLError, TimeoutError):
        raise ValueError('Apify API unavailable/timed out; no automatic retry; check your Apify run before rerunning') from None
    return rows


def evaluate(urls, minimum, required, rows):
    if not isinstance(rows, list):
        raise ValueError('API did not return a dataset array')
    mapped = {}
    for row in rows:
        if not isinstance(row, dict) or row.get('input') not in urls or row['input'] in mapped:
            raise ValueError('Unexpected or duplicate audit result')
        mapped[row['input']] = row
    results = []
    for url in urls:
        row = mapped.get(url)
        if not row or row.get('success') is not True or row.get('error'):
            raise ValueError('Missing/failed audit result: ' + url)
        grade = row.get('grade')
        if not isinstance(grade, str) or grade not in GRADES or not isinstance(row.get('headers'), dict):
            raise ValueError('Invalid grade or headers: ' + url)
        missing = []
        for header in required:
            entry = row['headers'].get(header)
            # The Actor may credit CSP framing as XFO protection; require an actual XFO value here.
            if not isinstance(entry, dict) or entry.get('present') is not True or not isinstance(entry.get('value'), str) or not entry['value'].strip():
                missing.append(header)
        passed = GRADES[grade] >= GRADES[minimum] and not missing
        results.append((url, grade, missing, passed))
    return results


def cell(value):
    return re.sub(r'[\r\n]', ' ', str(value)).replace('|', '&#124;').replace('<', '&lt;').replace('>', '&gt;')


def report(text):
    print(text)
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a', encoding='utf-8') as summary:
            summary.write(text + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', default='security-headers.yml')
    parser.add_argument('--api-base', default='https://api.apify.com/v2', help='Loopback mock override only')
    args = parser.parse_args()
    try:
        urls, minimum, required = load_config(args.config)
        token = os.environ.get('APIFY_TOKEN')
        if not token:
            raise ValueError('Set APIFY_TOKEN (GitHub Actions repository secret)')
        rows = run_audit(urls, token, args.api_base)
        results = evaluate(urls, minimum, required, rows)
        lines = [f'## Security headers gate (minimum {minimum})', '',
                 '| URL | Grade | Missing required headers | Gate |', '|---|---|---|---|']
        for url, grade, missing, passed in results:
            lines.append(f'| {cell(url)} | {grade} | {cell(", ".join(missing) or "None")} | {"PASS" if passed else "FAIL"} |')
        report('\n'.join(lines))
        return 0 if all(result[3] for result in results) else 1
    except (ValueError, OSError, yaml.YAMLError) as exc:
        report('## Security headers gate: operational error\n\n' + cell(exc))
        return 2


if __name__ == '__main__':
    sys.exit(main())
