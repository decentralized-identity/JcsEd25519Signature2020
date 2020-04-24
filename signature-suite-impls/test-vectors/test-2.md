# Test Vector 1
Keypair data is [Base58](https://tools.ietf.org/id/draft-msporny-base58-01.html) encoded. The input data is valid JSON.

## Private Key
```
z3nisqMdwW7nZdWomCfUyRaezHzKEBfwRbvaMcJAqaMSbmjxuRfS5qz4ff3QAf1A5sZT4ZMcxYoGjN4K1VsDV7b
```

## Public Key
```
4CcKDtU1JNGi8U4D8Rv9CHzfmF7xzaxEAPFA54eQjRHF
```

## Input Data

```json
{
  "id": "did:example:abcd",
  "publicKey": [
    {
      "id": "did:example:abcd#key-1",
      "type": "JcsEd25519Signature2020",
      "controller": "foo-issuer",
      "publicKeyBase58": "not-a-real-pub-key"
    }
  ],
  "authentication": null,
  "service": [
    {
      "id": "schema-id",
      "type": "schema",
      "serviceEndpoint": "service-endpoint"
    }
  ],
  "proof": {
    "type": "JcsEd25519Signature2020"
  }
}
```

## Signed Result

```json
{
  "id": "did:example:abcd",
  "publicKey": [
    {
      "id": "did:example:abcd#key-1",
      "type": "JcsEd25519Signature2020",
      "controller": "foo-issuer",
      "publicKeyBase58": "not-a-real-pub-key"
    }
  ],
  "authentication": null,
  "service": [
    {
      "id": "schema-id",
      "type": "schema",
      "serviceEndpoint": "service-endpoint"
    }
  ],
  "proof": {
    "signatureValue": "4qtzqwFxFYUifwfpPhxR6AABn94KnzWF768jcmjHHH8JYtUb4kAXxG6PttmJAbn3b6q1dfraXFdnUc1z2EGHqWdt",
    "type": "JcsEd25519Signature2020"
  }
}
```