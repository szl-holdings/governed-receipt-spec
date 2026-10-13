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

## Presentation and rights

This static informational page uses the unchanged approved SZL Orbit v2 icon
from [`szl-brand@4309f6f`](https://github.com/szl-holdings/szl-brand/tree/4309f6fce89179331b0b3ed8c99494e76c5be256).
Page code remains Apache-2.0; the embedded SZL artwork is attributed to SZL Holdings
under [CC BY 4.0](https://github.com/szl-holdings/szl-brand/blob/4309f6fce89179331b0b3ed8c99494e76c5be256/kit/LICENSE).
Selected KANCHAY palette roles are projected in the HTML file; the complete bundle
is not installed. Browser receipt verification remains **BLOCKED**.
