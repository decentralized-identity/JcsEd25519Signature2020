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
  "foo": "bar",
  "proof": {
    "type": "JcsEd25519Signature2020"
  }
}
```

## Signed Result

```json
{
  "foo": "bar",
  "proof": {
    "signatureValue": "4VCNeCSC4Daru6g7oij3QxUL2CS9FZkCYWRMUKyiLuPPK7GWFrM4YtYYQbmgyUXgGuxyKY5Wn1Mh4mmaRkbah4i4",
    "type": "JcsEd25519Signature2020"
  }
}
```