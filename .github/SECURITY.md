# Security Policy

## Supported version

This repository currently publishes a rolling specification and verifier from
the protected `main` branch; it does not yet publish versioned GitHub releases.
Security fixes are made against the current `main` revision. Historical
commits, forks, and copied verifier builds are not guaranteed to receive fixes.

## Report a vulnerability privately

Do **not** open a public issue with vulnerability details. Use GitHub's private
reporting form instead:

<https://github.com/szl-holdings/governed-receipt-spec/security/advisories/new>

Please include, when applicable:

- the exact commit or published verifier revision you tested;
- a minimal, synthetic receipt that reproduces the issue;
- the command, Python version, browser, or runtime used;
- the expected and observed result;
- the security impact and any known bypass conditions; and
- a proposed fix or regression test, if you have one.

Never include credentials, signing keys, tokens, or unredacted private receipt
content. Prefer synthetic data. If real evidence is essential, remove personal
and confidential fields before submitting it.

## In scope

Examples of security-relevant reports include:

- a malformed or tampered receipt that the verifier accepts;
- a DSSE, content-hash, chain, claim-binding, or schema validation bypass;
- fail-open behavior, unsafe parsing, or denial of service in the verifier;
- a workflow or action-supply-chain weakness in this repository; and
- drift where the public verifier serves different verifier bytes than the
  revision it claims to publish.

Feature requests, general support questions, disagreement with a receipt's
governance decision, and claims about model-output correctness are not security
vulnerabilities in this verifier specification.

## Handling and disclosure

This is a solo-maintained project, so no fixed response-time SLA is promised.
Reports are triaged according to exploitability and impact. Please keep the
report private while it is investigated and fixed. When appropriate, the fix,
regression evidence, affected revisions, and disclosure timing will be
coordinated through the private advisory.

No vulnerability-bounty payment is offered or implied by this policy.
