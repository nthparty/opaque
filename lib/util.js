module.exports = function (sodium, oprf) {
  const aead_encrypt = function (key, plaintext) {
    return sodium.crypto_aead_chacha20poly1305_encrypt(plaintext, null, null, new Uint8Array(8), key);
  };

  const aead_decrypt = function (key, ciphertext) {
    try {
      return sodium.crypto_aead_chacha20poly1305_decrypt(null, ciphertext, null, new Uint8Array(8), key);
    } catch (_) {
      return from_byte(255);
    }
  };

  const KDF = pwd => oprf.hashToPoint(pwd);
  const H = (x, m) => oprf.unmaskPoint(x, m);
  const H1 = x => oprf.maskPoint(x);
  const raise = (x, y) => oprf.scalarMult(x, y);
  const generic_hash = x => sodium.crypto_core_ristretto255_from_hash(x);
  const iterated_hash = function (x, t = 1000) {
    return sodium.crypto_generichash(x.length, t === 1 ? x : iterated_hash(x, t-1));
  };

  const F = function (k, x) {
    if (sodium.crypto_core_ristretto255_is_valid_point(x) === false || sodium.is_zero(x)) {
      x = oprf.hashToPoint(x);
    }

    const _H1_x_ = H1(x);
    const H1_x = _H1_x_.point;
    const mask = _H1_x_.mask;

    const H1_x_k = raise(H1_x, k);

    const unmasked = H(H1_x_k, mask);

    return unmasked;
  };

  const from_byte = function (n) {
    return new Uint8Array(32).fill(n);
  };

  const KE = function (p, x, P, X, X1) {
    const kx = oprf.scalarMult(X, x);
    const kp = oprf.scalarMult(P, p);
    const k = generic_hash(sodium.crypto_core_ristretto255_add(kx, kp));
    return k;
  };

  return {
    oprf_F: F,
    oprf_KDF: KDF,
    oprf_H: H,
    oprf_H1: H1,
    oprf_raise: raise,
    KE: KE,
    iterated_hash: iterated_hash,
    sodium_from_byte: from_byte,
    sodium_aead_encrypt: aead_encrypt,
    sodium_aead_decrypt: aead_decrypt
  };
};
