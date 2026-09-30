# Public verification fixtures

These existing public fixtures are copied byte-for-byte from pyca/cryptography
commit `ffde75a2b594822c740a2e4748b56c00548302bf` (50.0.1), under the attached
BSD license. No private key material was fetched or generated.

- `ec-public.pem`: [P-256 public key](https://github.com/pyca/cryptography/blob/ffde75a2b594822c740a2e4748b56c00548302bf/vectors/cryptography_vectors/asymmetric/PEM_Serialization/ec_public_key.pem), Git blob `6be3d673bb857d9c8f626557ee3fbe0bae4d3836`. It is unrelated to the supplied receipt chain, so that chain must fail verification with this key.
- `ecdsa-root.pem`: [public P-384 certificate](https://github.com/pyca/cryptography/blob/ffde75a2b594822c740a2e4748b56c00548302bf/vectors/cryptography_vectors/x509/ecdsa_root.pem), Git blob `bc20c1e149d3371640017b053e7ed007b6b6480f`. Tests extract only its public key and require rejection by the P-256-only verifier; no certificate-trust assertion is made.

Positive signatures remain the unchanged `examples/a11oy-khipu-chain.json` and
`tests/fixtures/cosign.pub`. The base64 negative changes only the payload while
retaining those existing signature bytes; it does not invent a signed receipt.
