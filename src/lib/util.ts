import type { Ciphertext } from '../types/local';
import type OPRF from 'oprf';
import type * as Sodium from 'libsodium-wrappers-sumo';

interface Utils {
  oprfF: (k: Uint8Array, x: string | Uint8Array) => Uint8Array;
  oprfKdf: (pwd: string) => Uint8Array;
  oprfH: (x: Uint8Array, m: Uint8Array) => Uint8Array;
  oprfH1: (x: Uint8Array) => IMaskedData;
  oprfRaise: (x: Uint8Array, y: Uint8Array) => Uint8Array;
  keyExchange: (p: Uint8Array, x: Uint8Array, P: Uint8Array, X: Uint8Array, X1: Uint8Array, P1: Uint8Array) => Uint8Array;
  iteratedHash: (x: Uint8Array, t?: number) => Uint8Array;
  sodiumFromByte: (n: number) => Uint8Array;
  sodiumAeadEncrypt: (key: Uint8Array, plaintext: string | Uint8Array) => Ciphertext;
  sodiumAeadDecrypt: (key: Uint8Array, ciphertext: Ciphertext) => Uint8Array;
}

type IMaskedData = ReturnType<OPRF['maskPoint']>;

export = (sodium: typeof Sodium, oprf: OPRF) => {
  const sodiumAeadEncrypt: Utils['sodiumAeadEncrypt'] = (key, plaintext) => {
    const raw_ciphertext = sodium.crypto_aead_chacha20poly1305_encrypt(
      plaintext,
      null,
      null,
      new Uint8Array(8),
      key
    );
    const mac_tag = sodium.crypto_auth_hmacsha512(raw_ciphertext, key);
    return { mac_tag, body: raw_ciphertext };
  };

  const sodiumAeadDecrypt: Utils['sodiumAeadDecrypt'] = (key, ciphertext) => {
    if (sodium.crypto_auth_hmacsha512_verify(ciphertext.mac_tag, ciphertext.body, key)) {
      try {
        return sodium.crypto_aead_chacha20poly1305_decrypt(
          null,
          ciphertext.body,
          null,
          new Uint8Array(8),
          key
        );
      } catch (_) {
        return sodiumFromByte(255);
      }
    } else {
      throw new Error(
        'Invalid Message Authentication Code.  Someone may have tampered with the ciphertext.'
      );
    }
  };

  const oprfKdf: Utils['oprfKdf'] = (pwd) => oprf.hashToPoint(pwd);
  const oprfH: Utils['oprfH'] = (x, m) => oprf.unmaskPoint(x, m);
  const oprfH1: Utils['oprfH1'] = (x) => oprf.maskPoint(x);
  const oprfRaise: Utils['oprfRaise'] = (x, y) => oprf.scalarMult(x, y);
  const genericHash = (x: Uint8Array): Uint8Array => sodium.crypto_core_ristretto255_from_hash(x);
  const iteratedHash: Utils['iteratedHash'] = (x, t = 1000) => {
    return sodium.crypto_generichash(x.length, t === 1 ? x : iteratedHash(x, t - 1));
  };

  const oprfF: Utils['oprfF'] = (k, x) => {
    if (!sodium.crypto_core_ristretto255_is_valid_point(x) || !(x instanceof Uint8Array) || sodium.is_zero(x)) {
      // The type-cast here assumes that the value always gets passed to
      // `encodeURIComponent`, which coerces `Uint8Array` objects to strings anyway:
      x = oprf.hashToPoint(x as string);
    }

    const _H1_x_ = oprfH1(x);
    const H1_x = _H1_x_.point;
    const mask = _H1_x_.mask;

    const H1_x_k = oprfRaise(H1_x, k);

    const unmasked = oprfH(H1_x_k, mask);

    return unmasked;
  };

  const sodiumFromByte: Utils['sodiumFromByte'] = (n) => {
    return new Uint8Array(32).fill(n);
  };

  const keyExchange: Utils['keyExchange'] = (p, x, P, X, X1, P1) => {
    // Note: P1 and X1 to be used in a future authentication feature.  The below (unauthenticated) key exchange suffices for now.
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
    keyExchange,
    iteratedHash,
    sodiumFromByte,
    sodiumAeadEncrypt,
    sodiumAeadDecrypt,
  };
};
