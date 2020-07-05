module.exports = function (io, sodium, oprf) {
  const util = require('./util.js')(sodium, oprf);

  // Sign up as a new user
  const client_register = function (password, user_id, op_id) {
    op_id = op_id + ':pake_init';
    var get = io.get.bind(null, op_id);
    var give = io.give.bind(null, op_id);

    const pw = util.oprf_KDF(password);
    give('sid', user_id);
    give('pw', pw);

    return new Promise(function (resolve) {
      get('registered').then(function (bool) {
        resolve(bool);
      });
    });
  };

  // Register a new user for the first time
  const server_register = function (t, op_id) {
    op_id = op_id + ':pake_init';
    var get = io.get.bind(null, op_id);
    var give = io.give.bind(null, op_id);

    return new Promise(function (resolve) {
      get('sid').then(function (sid) {
        get('pw').then(function (pw) {
          const ks = sodium.crypto_core_ristretto255_scalar_random();
          const rw = util.iterated_hash(util.oprf_F(ks, pw), t);
          const ps = sodium.crypto_core_ristretto255_scalar_random();
          const pu = sodium.crypto_core_ristretto255_scalar_random();
          const Ps = sodium.crypto_scalarmult_ristretto255_base(ps);
          const Pu = sodium.crypto_scalarmult_ristretto255_base(pu);
          const c = {
            pu: util.sodium_aead_encrypt(rw, pu),
            Pu: util.sodium_aead_encrypt(rw, Pu),
            Ps: util.sodium_aead_encrypt(rw, Ps)
          };
          const user_record = {id: sid, pepper: {ks: ks, ps: ps, Ps: Ps, Pu: Pu, c: c}};

          give('registered', true);
          resolve(user_record);
        });
      });
    });
  };

  // Try to log in
  const client_authenticate = function (password, user_id, t, op_id) {
    op_id = op_id + ':pake';
    var get = io.get.bind(null, op_id);
    var give = io.give.bind(null, op_id);

    return new Promise(function (resolve) {
      const r = sodium.crypto_core_ristretto255_scalar_random();
      const xu = sodium.crypto_core_ristretto255_scalar_random();

      const pw = util.oprf_KDF(password);
      const _H1_x_ = util.oprf_H1(pw);
      const H1_x = _H1_x_.point;
      const mask = _H1_x_.mask;
      const a = util.oprf_raise(H1_x, r);

      const Xu = sodium.crypto_scalarmult_ristretto255_base(xu);
      give('alpha', a);
      give('Xu', Xu);

      get('beta').then(function (b) {
        if (sodium.crypto_core_ristretto255_is_valid_point(b)) {
          get('c').then(function (c) {
            const r_inv = sodium.crypto_core_ristretto255_scalar_invert(r);
            const rw = util.iterated_hash(util.oprf_H(util.oprf_raise(b, r_inv), mask), t);
            const pu = util.sodium_aead_decrypt(rw, c.pu);
            if (sodium.crypto_core_ristretto255_is_valid_point(pu)) {
              const Pu = util.sodium_aead_decrypt(rw, c.Pu);
              const Ps = util.sodium_aead_decrypt(rw, c.Ps);

              get('Xs').then(function (Xs) {
                const K = util.KE(pu, xu, Ps, Xs, Xu);
                const SK = util.oprf_F(K, util.sodium_from_byte(0));
                const As = util.oprf_F(K, util.sodium_from_byte(1));
                const Au = util.oprf_F(K, util.sodium_from_byte(2));

                get('As').then(function (__As) {
                  if (sodium.compare(As, __As) === 0) {  // The comparable value of 0 means As equals __As
                    give('Au', Au);
                    get('authenticated').then(function (success) {
                      if (success) {
                        const token = sodium.to_hex(SK);
                        resolve(token);
                      } else {
                        resolve(false);
                      }
                    });
                  } else {
                    console.log("client_authenticated_3 false " + user_id);
                    give('client_authenticated', false);
                    resolve(false);
                  }
                });
              });
            } else {
              console.log("client_authenticated_2 false " + user_id);
              give('client_authenticated', false);
              resolve(false);
            }
          });
        } else {
          console.log("client_authenticated_1 false " + user_id);
          give('client_authenticated', false);
          resolve(false);
        }
      });
    });
  };

  // Authenticate a user
  const server_authenticate = function (user_id, pepper, op_id) {
    op_id = op_id + ':pake';
    var get = io.get.bind(null, op_id);
    var give = io.give.bind(null, op_id);

    return new Promise(function (resolve, reject) {
      get('alpha').then(function (a) {
        if (sodium.crypto_core_ristretto255_is_valid_point(a)) {
          const xs = sodium.crypto_core_ristretto255_scalar_random();
          const b = util.oprf_raise(a, pepper.ks);
          const Xs = sodium.crypto_scalarmult_ristretto255_base(xs);

          get('Xu').then(function (Xu) {
            const K = util.KE(pepper.ps, xs, pepper.Pu, Xu, Xs);
            const SK = util.oprf_F(K, util.sodium_from_byte(0));
            const As = util.oprf_F(K, util.sodium_from_byte(1));
            const Au = util.oprf_F(K, util.sodium_from_byte(2));

            give('beta', b);
            give('Xs', Xs);
            give('c', pepper.c);
            give('As', As);

            get('Au').then(function (__Au) {
              if (sodium.compare(Au, __Au) === 0) {  // The comparable value of 0 means equality
                give('authenticated', true);
                const token = sodium.to_hex(SK);
                resolve(token);
              } else {
                console.log("Authentication failed.  Wrong password for " + user_id + ".");
                give('authenticated', false);
                reject(new Error("Authentication failed.  Wrong password for " + user_id + "."));
              }
            });
          });
        } else {
          console.log("Authentication failed.  Alpha is not a group element.");
          give('authenticated', false);
          reject(new Error("Authentication failed.  Alpha is not a group element."));
        }
      });
    });
  };

  return {
    client_register: client_register,
    server_register: server_register,
    client_authenticate: client_authenticate,
    server_authenticate: server_authenticate
  };
};
