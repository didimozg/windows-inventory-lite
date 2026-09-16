# Test fixtures

`wil-test-fixture-key` (RSA), `wil-test-fixture-key-ed25519`, `wil-test-fixture-key-ecdsa256`, `wil-test-fixture-key-ecdsa384`, and `wil-test-fixture-key-ecdsa521` are freshly generated, disposable private keys created solely for this project's `Convert-OpenSshKeyToPpk` tests. None has ever been used against any real host and none grants access to anything, so they are safe to have checked into this repository despite looking like real private keys. If a secret scanner (for example GitHub push protection) flags any of them, this file is the explanation.
