module.exports = function (sodium, oprf) {
  const aead_encrypt = function (key, plaintext) {
    return sodium.crypto_aead_chacha20poly1305_encrypt(plaintext, null, null, new Uint8Array(8), key);
  };

  const aead_decrypt = function (key, ciphertext) {
    return sodium.crypto_aead_chacha20poly1305_decrypt(null, ciphertext, null, new Uint8Array(8), key);
  };

  const KDF = pwd => oprf.hashToPoint(pwd);
  const H = (x, m) => oprf.unmaskPoint(x, m);
  const H1 = x => oprf.maskPoint(x);
  const raise = (x, y) => oprf.scalarMult(x, y);

  const generic_hash = x => sodium.crypto_core_ristretto255_from_hash(x);

  const F = function (k, x) {
    // const x = KDF(input);
    x = oprf.hashToPoint(x);

    const _H1_x_ = H1(x);
    const H1_x = _H1_x_.point;
    const mask = _H1_x_.mask;

    const H1_x_k = raise(H1_x, k);

    const unmasked = H(H1_x_k, mask);

    return unmasked;
  };

  const from_byte = function (n) {
    const hex_byte = n.toString(16).padStart(2, '0');
    return sodium.from_hex(Array(32).fill(hex_byte).join(''));
  };

  const KE = function (p, x, P, X, X1) {
    console.log(sodium.crypto_core_ristretto255_is_valid_point(p),
                sodium.crypto_core_ristretto255_is_valid_point(x),
                sodium.crypto_core_ristretto255_is_valid_point(P),
                sodium.crypto_core_ristretto255_is_valid_point(X),
                sodium.crypto_core_ristretto255_is_valid_point(X1));




    const e = generic_hash(X);//, ssid1);
    const e1 = X1;//generic_hash(from_byte(0));//, ssid1);
    const ep = sodium.crypto_core_ristretto255_scalar_mul(e1, p);
    const x_plus_ep = sodium.crypto_core_ristretto255_scalar_add(x, ep);

    const Pe = oprf.scalarMult(P, e);
    const XPe = sodium.crypto_core_ristretto255_add(X, Pe);

    console.log(generic_hash(oprf.scalarMult(XPe, x_plus_ep)));
    return generic_hash(oprf.scalarMult(XPe, x_plus_ep));
  };

  return {
    oprf_F: F,
    oprf_KDF: KDF,
    oprf_H: H,
    oprf_H1: H1,
    oprf_raise: raise,
    KE: KE,
    sodium_from_byte: from_byte,
    sodium_aead_encrypt: aead_encrypt,
    sodium_aead_decrypt: aead_decrypt
  };
};
