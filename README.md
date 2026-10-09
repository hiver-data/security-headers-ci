# Security headers CI gate

Catch a missing HSTS or CSP header after deployment, or check it every week.
This GitHub Actions template runs [hiver/website-security-headers-audit](https://apify.com/hiver/website-security-headers-audit?utm_source=github&utm_campaign=security-headers-ci)
with your own Apify token, compares each URL's grade to a YAML policy, and writes a table to the Actions job summary. A policy failure makes the job red.
The script and workflow are free; the Actor is pay-per-use on your Apify account.

## Setup in 3 steps

1. Copy `security_gate.py`, `requirements.txt` and `security-headers.yml` into your repository (or fork this repo). Install the template as `.github/workflows/security-headers.yml`: run `mkdir -p .github/workflows && cp workflow-template/security-headers.yml .github/workflows/security-headers.yml` from the repository root. The template is inactive until you copy it; when copying into another repository, take it from this repo's `workflow-template/` directory.
2. Create an Apify API token with permission to run the linked Actor. Add it under GitHub **Settings → Secrets and variables → Actions → New repository secret**, named `APIFY_TOKEN`. Never commit it. Your account needs enough credit and access to the Actor.
3. Replace the example root URL in `security-headers.yml` with 1–5 public sites you manage, choose `minimum_grade` and `required_headers`, then push to `main` or select **Actions → Security headers gate → Run workflow**. For a true post-deploy gate, copy the audit job into your deployment workflow and add `needs: deploy`; an ordinary push alone does not guarantee deployment has finished.

```yaml
urls:
  - https://www.bbc.co.uk/
minimum_grade: B
required_headers:
  - strict-transport-security
  - content-security-policy
  - x-content-type-options
```

The BBC URL is a public configuration example, not a promise that it will keep passing. Use your own site before enabling the gate. The weekly schedule is Monday 07:23 UTC; GitHub may delay scheduled jobs and runs them from the default branch.

## Policy and outcomes

Grades rank A > B > C > D > F (no E). A grade equal to the minimum passes. Required names are case-insensitive and must be one of `strict-transport-security`, `content-security-policy`, `x-frame-options`, `x-content-type-options`, `referrer-policy`, `permissions-policy`. Use `required_headers: []` for grade-only checks.

* Exit 0: every requested URL meets the grade floor and every required header is present with a non-empty observed value.
* Exit 1: at least one valid audit row is below the floor or lacks a required header. All URLs appear in the summary, including passing ones.
* Exit 2: configuration, credentials, network/API, missing rows, failed audit or malformed data. This fails closed rather than reporting a false pass; it is not a measured header regression.

Header presence is not proof that a policy is safe. The Actor's grade also considers usability and other checklist findings. CSP frame-ancestors can supply framing protection without an actual X-Frame-Options header; this gate requires an actual XFO value if you explicitly require `x-frame-options`. Choose CSP instead if that's your policy.

Root http(s) URLs or bare domains (HTTPS implied), without paths (except `/`), ports, credentials, query strings or fragments are accepted: the Actor audits the home page, not an arbitrary route. Results are matched to `input`, not redirected `finalUrl`, so a redirected page cannot hide a missing requested row. Duplicate origins and unexpected or duplicate rows are errors.

## Scope, cost and limitations

This is an absolute policy gate, not a historical baseline/diff, penetration test, vulnerability scan or uptime check. The Actor measures observed response headers; an error-page response can have a grade too. Inspect its full results in Apify when investigating. No private URLs, login bypass or block circumvention is provided.

Each invocation audits at most five URLs, with a 120-second Actor timeout, 256 MB memory and a $0.05 maximum Actor charge parameter. This parameter is not a promise of zero platform charges: see Apify's billing rules and the current Store price. The script does not retry the run POST: after a timeout, inspect your Apify runs before running again to avoid duplicate charges. APIFY_TOKEN goes in the Authorization header, never the URL or job output. Do not run untrusted pull-request code with this secret.

## Dated independent bench

Board bench, **2026-10-08 03:24:36 UTC**, build **0.1.7**, 8 items:
accuracy **100% vs 90%** for the best measured competitor, `psx/security-headers-tls-audit`; completeness **100% vs 100%** (tie); Store price in those runs **$2.02 vs $9.88 per 1,000 items**. Runtime **3.4 s vs 2.7 s** for the fastest measured competitor, `ninhothedev/security-headers-checker`: no fastest claim. Prices are historical run measurements, not a current price guarantee, and this small bench is not a claim about every site.

## Offline verification (no Apify spend)

```sh
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
```

Tests start a loopback mock Apify endpoint and execute the real CLI. Fixtures preserve the `input`, `success`, `grade` and `headers` fields from the board's existing cloud run `zRVWvU3IcUAeM7dKU` (build 0.1.8, 2026-10-09 20:41 UTC). They are historical observations, not newly fetched live grades: BBC grade B passes a B policy; Wikipedia grade F fails it. A grade-F minimum also proves a missing CSP alone fails; a grade-only policy proves it passes. No cloud runs are created by tests. Additional checks cover all grade thresholds, absent rows, failures, malformed data and summary output. See `tests/fixtures/provenance.json`.

Local use: set APIFY_TOKEN in your environment using your secret manager, then run `python security_gate.py`. Dependencies: Python 3.10+ and PyYAML. API override is restricted to loopback mock tests so it cannot silently send your token to an arbitrary host.
