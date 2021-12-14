module.exports = (sodium, oprf) => {
  const sodiumAeadEncrypt = (key, plaintext) => {
    let raw_ciphertext = sodium.crypto_aead_chacha20poly1305_encrypt(plaintext, null, null, new Uint8Array(8), key);
    let mac_tag = sodium.crypto_auth_hmacsha512(raw_ciphertext, key);
    return { mac_tag, body: raw_ciphertext };
  };

  const sodiumAeadDecrypt = (key, ciphertext) => {
    if (sodium.crypto_auth_hmacsha512_verify(ciphertext.mac_tag, ciphertext.body, key) === true) {
      try {
        return sodium.crypto_aead_chacha20poly1305_decrypt(null, ciphertext.body, null, new Uint8Array(8), key);
      } catch (_) {
        return sodiumFromByte(255);
      }
    } else {
      throw new Error("Invalid Message Authentication Code.  Someone may have tampered with the ciphertext.");
    }
  };

  const oprfKdf = pwd => oprf.hashToPoint(pwd);
  const oprfH = (x, m) => oprf.unmaskPoint(x, m);
  const oprfH1 = x => oprf.maskPoint(x);
  const oprfRaise = (x, y) => oprf.scalarMult(x, y);
  const genericHash = x => sodium.crypto_core_ristretto255_from_hash(x);
  const iteratedHash = (x, t = 1000) => {
    return sodium.crypto_generichash(x.length, t === 1 ? x : iteratedHash(x, t-1));
  };

  const oprfF = (k, x) => {
    if (sodium.crypto_core_ristretto255_is_valid_point(x) === false || sodium.is_zero(x)) {
      x = oprf.hashToPoint(x);
    }

    const _H1_x_ = oprfH1(x);
    const H1_x = _H1_x_.point;
    const mask = _H1_x_.mask;

    const H1_x_k = oprfRaise(H1_x, k);

    const unmasked = oprfH(H1_x_k, mask);

    return unmasked;
  };

  const sodiumFromByte = (n) => {
    return new Uint8Array(32).fill(n);
  };

  const KE = (p, x, P, X, X1) => {
    const kx = oprf.scalarMult(X, x);
    const kp = oprf.scalarMult(P, p);
    const k = genericHash(sodium.crypto_core_ristretto255_add(kx, kp));
    return k;
  };

  return {
    oprfF,
    oprfKdf,
    oprfH,
    oprfH1,
    oprfRaise,
    KE,
    iteratedHash,
    sodiumFromByte,
    sodiumAeadEncrypt,
    sodiumAeadDecrypt
  };
};
