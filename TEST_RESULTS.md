# Offline acceptance evidence

Executed `python -m unittest discover -s tests -v`: 11 tests passed, 25.031 seconds, Python 3.13 / PyYAML 6.0.3. No live Apify call or spend.

Real cloud fixtures from run zRVWvU3IcUAeM7dKU, build 0.1.8 (board test 2026-10-09 20:41 UTC), copied fields unchanged:
- BBC grade B, minimum B, required CSP/HSTS: exit 0, summary PASS.
- Wikipedia grade F, minimum B, no required headers: exit 1, summary FAIL.
- Wikipedia grade F, minimum F, required CSP missing: exit 1, summary FAIL.
- Wikipedia grade F, minimum F, no required headers: exit 0.

30 subcases exercise two real rows × five grade floors × three header policies via loopback HTTP and the actual CLI. Other tests exercise mixed/out-of-order results, malformed/missing/duplicate/failed rows (exit 2), API 401 (exit 2, no retry), bad config, CSP framing without actual XFO, remote API override refusal and matching stdout/GitHub summary with no mock credential leaked.

README bench numbers checked against board RESULT.md: 2026-10-08T03:24:36Z/build0.1.7; accuracy100%/90%, completeness100%/100%, $2.02/$9.88 per1k, runtime3.4s/fastest2.7s. Existing security Actor daily health at 2026-10-09T18:34:28Z: SUCCEEDED, 5 items, 0 sampled errors. This asset changes no Actor code or deployed build; no paid re-bench requested.
