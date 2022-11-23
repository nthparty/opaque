import type { IO, IOData, Tag } from '../types/io';
import type { Opaque } from '../types/local';
import type * as Sodium from 'libsodium-wrappers-sumo';
import type OPRF from 'oprf';
import utilFactory from './util';

type BoundGet = <T extends Tag>(tag: T) => Promise<IOData[T]>;
type BoundGive = <T extends Tag>(tag: T, msg: IOData[T]) => void;

export = (io: IO, sodium: typeof Sodium, oprf: OPRF): Opaque => {
  const util = utilFactory(sodium, oprf);

  // Sign up as a new user
  const clientRegister: Opaque['clientRegister'] = async (password, user_id, op_id) => {
    op_id = op_id + ':pake_init';
    const get = io.get.bind(null, op_id) as BoundGet;
    const give = io.give.bind(null, op_id) as BoundGive;

    const password_digest = util.oprfKdf(password);
    give('session_id', user_id);
    give('password_digest', password_digest);

    return await get('registered');
  };

  // Register a new user for the first time
  const serverRegister: Opaque['serverRegister'] = async (t, op_id) => {
    op_id = op_id + ':pake_init';
    const get = io.get.bind(null, op_id) as BoundGet;
    const give = io.give.bind(null, op_id) as BoundGive;

    const session_id = await get('session_id');
    const password_digest = await get('password_digest');

    const server_oprf_key = sodium.crypto_core_ristretto255_scalar_random();
    const user_symmetric_key = util.iteratedHash(util.oprfF(server_oprf_key, password_digest), t);
    const secret_server_scalar = sodium.crypto_core_ristretto255_scalar_random();
    const server_user_scalar = sodium.crypto_core_ristretto255_scalar_random();
    const public_server_point = sodium.crypto_scalarmult_ristretto255_base(secret_server_scalar);
    const public_user_point = sodium.crypto_scalarmult_ristretto255_base(server_user_scalar);
    const asymmetric_keys_enc = {
      secret_user_scalar_enc: util.sodiumAeadEncrypt(user_symmetric_key, server_user_scalar),
      public_user_point_enc: util.sodiumAeadEncrypt(user_symmetric_key, public_user_point),
      public_server_point_enc: util.sodiumAeadEncrypt(user_symmetric_key, public_server_point),
    };

    const user_record = { id: session_id, pepper: { server_oprf_key, secret_server_scalar, public_server_point, public_user_point, asymmetric_keys_enc } };
    give('registered', true);

    return user_record;
  };

  // Try to log in
  const clientAuthenticate: Opaque['clientAuthenticate'] = async (password, user_id, t, op_id) => {
    op_id = op_id + ':pake';
    const get = io.get.bind(null, op_id) as BoundGet;
    const give = io.give.bind(null, op_id) as BoundGive;

    const blinding_scalar = sodium.crypto_core_ristretto255_scalar_random();
    const client_secret_key = sodium.crypto_core_ristretto255_scalar_random();

    const password_digest = util.oprfKdf(password);
    const _H1_x_ = util.oprfH1(password_digest);
    const H1_x = _H1_x_.point;
    const mask = _H1_x_.mask;
    const a = util.oprfRaise(H1_x, blinding_scalar);

    const ephemeral_public_user_point = sodium.crypto_scalarmult_ristretto255_base(client_secret_key);
    give('alpha', a);
    give('ephemeral_public_user_point', ephemeral_public_user_point);

    const b = await get('beta');

    if (!sodium.crypto_core_ristretto255_is_valid_point(b)) {
      console.debug('client_authenticated_1 false ' + user_id);
      give('client_authenticated', false);
      throw new Error('client_authenticated_1 false');
    }

    const asymmetric_keys_enc = await get('asymmetric_keys_enc');
    const blinding_scalar_inv = sodium.crypto_core_ristretto255_scalar_invert(blinding_scalar);
    const user_symmetric_key = util.iteratedHash(util.oprfH(util.oprfRaise(b, blinding_scalar_inv), mask), t);
    const secret_user_scalar = util.sodiumAeadDecrypt(user_symmetric_key, asymmetric_keys_enc.secret_user_scalar_enc);

    if (!sodium.crypto_core_ristretto255_is_valid_point(secret_user_scalar)) {
      console.debug('client_authenticated_2 false ' + user_id);
      give('client_authenticated', false);
      throw new Error('client_authenticated_2 false');
    }

    const public_user_point = util.sodiumAeadDecrypt(user_symmetric_key, asymmetric_keys_enc.public_user_point_enc);
    const public_server_point = util.sodiumAeadDecrypt(user_symmetric_key, asymmetric_keys_enc.public_server_point_enc);
    const ephemeral_public_server_point = await get('ephemeral_public_server_point');
    const K = util.keyExchange(secret_user_scalar, client_secret_key, public_server_point, ephemeral_public_server_point, ephemeral_public_user_point, public_user_point);
    const SK = util.oprfF(K, util.sodiumFromByte(0));
    const computed_server_authentication_token = util.oprfF(K, util.sodiumFromByte(1));
    const user_authentication_token = util.oprfF(K, util.sodiumFromByte(2));

    const actual_server_authentication_token = await get('server_authentication_token');

    if (sodium.compare(computed_server_authentication_token, actual_server_authentication_token) !== 0) {
      // The comparable value of 0 means As equals __As
      console.debug('client_authenticated_3 false ' + user_id);
      give('client_authenticated', false);
      throw new Error('client_authenticated_3 false');
    }

    give('user_authentication_token', user_authentication_token);

    const success = await get('authenticated');
    if (success) {
      const token = sodium.to_hex(SK);
      return token;
    } else {
      console.debug('client_authenticated_4 false ' + user_id);
      give('client_authenticated', false);
      throw new Error('client_authenticated_4 false');
    }
  };

  // Authenticate a user
  const serverAuthenticate: Opaque['serverAuthenticate'] = async (user_id, pepper, op_id) => {
    op_id = op_id + ':pake';
    const get = io.get.bind(null, op_id) as BoundGet;
    const give = io.give.bind(null, op_id) as BoundGive;

    const a = await get('alpha');
    if (!sodium.crypto_core_ristretto255_is_valid_point(a)) {
      console.debug('Authentication failed.  Alpha is not a group element.');
      give('authenticated', false);
      throw new Error('Authentication failed.  Alpha is not a group element.');
    }
    const ephemeral_secret_client_scalar = sodium.crypto_core_ristretto255_scalar_random();
    const b = util.oprfRaise(a, pepper.server_oprf_key);
    const ephemeral_public_server_point = sodium.crypto_scalarmult_ristretto255_base(ephemeral_secret_client_scalar);

    const ephemeral_public_user_point = await get('ephemeral_public_user_point');
    const K = util.keyExchange(pepper.secret_server_scalar, ephemeral_secret_client_scalar, pepper.public_user_point, ephemeral_public_user_point, ephemeral_public_server_point, pepper.public_server_point);
    const SK = util.oprfF(K, util.sodiumFromByte(0));
    const server_authentication_token = util.oprfF(K, util.sodiumFromByte(1));
    const valid_user_authentication_token = util.oprfF(K, util.sodiumFromByte(2));

    give('beta', b);
    give('ephemeral_public_server_point', ephemeral_public_server_point);
    give('asymmetric_keys_enc', pepper.asymmetric_keys_enc);
    give('server_authentication_token', server_authentication_token);

    const user_authentication_token_from_client = await get('user_authentication_token');
    if (sodium.compare(valid_user_authentication_token, user_authentication_token_from_client) === 0) {
      // The comparable value of 0 means equality
      give('authenticated', true);
      const token = sodium.to_hex(SK);
      return token;
    } else {
      console.debug('Authentication failed.  Wrong password for ' + user_id);
      give('authenticated', false);
      throw new Error('Authentication failed.  Wrong password for ' + user_id);
    }
  };

  return {
    clientRegister,
    serverRegister,
    clientAuthenticate,
    serverAuthenticate,
  };
};
