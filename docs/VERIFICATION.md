# Verification Record

This record distinguishes mocked verification from live integration testing.

## Automated local checks

- Python compilation: passed with Python 3.11.9 (`python -m compileall -q .`).
- Ruff safety lint: passed (`E9`, `F63`, `F7`, and `F82`).
- pytest: 31 of 31 tests passed with pytest 9.2.0.
- Coverage: 20% overall. The new guardrails have focused coverage: command policy 76%, LLM parsing 89%, scope policy 81%, and SSH client 34%. External integrations and the legacy collection code remain intentionally unexecuted in CI.
- Dependency audit: no known vulnerabilities reported by `pip-audit` on October 30, 2026. The editable local package itself was skipped because it is not published on PyPI.
- Secret scan: no findings in the release candidate after excluding generated caches and applying explicit allow-list comments to synthetic test credentials.

## Mocked behaviors

- Target authorization and active acknowledgement.
- Remote command policy.
- LLM JSON parsing and error handling.
- Nmap XML parsing using a fake Kali executor.
- URL sanitization and summary truncation.

## Live integrations

- VirtualBox inventory: the local CLI was detected, but no virtual machines were registered or running. Kali SSH and remote tools therefore could not be exercised safely.
- Groq: not called during automated tests.
- Gemini: not called during automated tests.
- Public targets: intentionally not contacted.

These results verify the local controls and parsing behavior. They do not claim that a live Kali VM, Groq account, Gemini account, or public target was exercised.

