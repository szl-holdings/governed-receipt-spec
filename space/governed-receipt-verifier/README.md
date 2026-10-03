---
title: governed-receipt-verifier
emoji: "🧾"
sdk: static
app_file: index.html
pinned: false
license: apache-2.0
---

# Governed receipt verifier status

The browser verifier is **BLOCKED**. This Space is an informational page; it
does not accept a receipt or return a verification verdict. The former browser
prototype was not qualified against the current receipt verifier and could
report PASS without validating claimed hashes or cryptographic signatures.

Use the maintained [offline Python verifier](https://github.com/szl-holdings/governed-receipt-spec)
with a public key obtained and trusted independently. A successful integrity
check alone does not authenticate the signer or authorize a governed action.

Source for this informational page:
[`space/governed-receipt-verifier/`](https://github.com/szl-holdings/governed-receipt-spec/tree/main/space/governed-receipt-verifier).
