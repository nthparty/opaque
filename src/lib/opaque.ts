import type { IO, IOData, Tag } from "../types/io";
import type { Opaque } from "../types/local";
import type * as Sodium from "libsodium-wrappers-sumo";
import type OPRF from "oprf";
import utilFactory from "./util";

type BoundGet = <T extends Tag>(tag: T) => Promise<IOData[T]>;
type BoundGive = <T extends Tag>(tag: T, msg: IOData[T]) => void;

export = (io: IO, sodium: typeof Sodium, oprf: OPRF): Opaque => {
  const util = utilFactory(sodium, oprf);

  // Sign up as a new user
  const clientRegister: Opaque["clientRegister"] = async (password, user_id, op_id) => {
    op_id = op_id + ":pake_init";
    const get = io.get.bind(null, op_id) as BoundGet;
    const give = io.give.bind(null, op_id) as BoundGive;

    const pw = util.oprfKdf(password);
    give("sid", user_id);
    give("pw", pw);

    return await get("registered");
  };

  // Register a new user for the first time
  const serverRegister: Opaque["serverRegister"] = async (t, op_id) => {
    op_id = op_id + ":pake_init";
    const get = io.get.bind(null, op_id) as BoundGet;
    const give = io.give.bind(null, op_id) as BoundGive;

    const sid = await get("sid");
    const pw = await get("pw");

    const ks = sodium.crypto_core_ristretto255_scalar_random();
    const rw = util.iteratedHash(util.oprfF(ks, pw), t);
    const ps = sodium.crypto_core_ristretto255_scalar_random();
    const pu = sodium.crypto_core_ristretto255_scalar_random();
    const Ps = sodium.crypto_scalarmult_ristretto255_base(ps);
    const Pu = sodium.crypto_scalarmult_ristretto255_base(pu);
    const c = {
      pu: util.sodiumAeadEncrypt(rw, pu),
      Pu: util.sodiumAeadEncrypt(rw, Pu),
      Ps: util.sodiumAeadEncrypt(rw, Ps),
    };

    const user_record = { id: sid, pepper: { ks: ks, ps: ps, Ps: Ps, Pu: Pu, c: c } };
    give("registered", true);

    return user_record;
  };

  // Try to log in
  const clientAuthenticate: Opaque["clientAuthenticate"] = async (password, user_id, t, op_id) => {
    op_id = op_id + ":pake";
    const get = io.get.bind(null, op_id) as BoundGet;
    const give = io.give.bind(null, op_id) as BoundGive;

    const r = sodium.crypto_core_ristretto255_scalar_random();
    const xu = sodium.crypto_core_ristretto255_scalar_random();

    const pw = util.oprfKdf(password);
    const _H1_x_ = util.oprfH1(pw);
    const H1_x = _H1_x_.point;
    const mask = _H1_x_.mask;
    const a = util.oprfRaise(H1_x, r);

    const Xu = sodium.crypto_scalarmult_ristretto255_base(xu);
    give("alpha", a);
    give("Xu", Xu);

    const b = await get("beta");

    if (!sodium.crypto_core_ristretto255_is_valid_point(b)) {
      console.debug("client_authenticated_1 false " + user_id);
      give("client_authenticated", false);
      throw new Error("client_authenticated_1 false");
    }

    const c = await get("c");
    const r_inv = sodium.crypto_core_ristretto255_scalar_invert(r);
    const rw = util.iteratedHash(util.oprfH(util.oprfRaise(b, r_inv), mask), t);
    const pu = util.sodiumAeadDecrypt(rw, c.pu);

    if (!sodium.crypto_core_ristretto255_is_valid_point(pu)) {
      console.debug("client_authenticated_2 false " + user_id);
      give("client_authenticated", false);
      throw new Error("client_authenticated_2 false");
    }

    const Pu = util.sodiumAeadDecrypt(rw, c.Pu);
    const Ps = util.sodiumAeadDecrypt(rw, c.Ps);
    const Xs = await get("Xs");
    const K = util.KE(pu, xu, Ps, Xs, Xu);
    const SK = util.oprfF(K, util.sodiumFromByte(0));
    const As = util.oprfF(K, util.sodiumFromByte(1));
    const Au = util.oprfF(K, util.sodiumFromByte(2));

    const __As = await get("As");

    if (sodium.compare(As, __As) !== 0) {
      // The comparable value of 0 means As equals __As
      console.debug("client_authenticated_3 false " + user_id);
      give("client_authenticated", false);
      throw new Error("client_authenticated_3 false");
    }

    give("Au", Au);

    const success = await get("authenticated");
    if (success) {
      const token = sodium.to_hex(SK);
      return token;
    } else {
      console.debug("client_authenticated_4 false " + user_id);
      give("client_authenticated", false);
      throw new Error("client_authenticated_4 false");
    }
  };

  // Authenticate a user
  const serverAuthenticate: Opaque["serverAuthenticate"] = async (user_id, pepper, op_id) => {
    op_id = op_id + ":pake";
    const get = io.get.bind(null, op_id) as BoundGet;
    const give = io.give.bind(null, op_id) as BoundGive;

    const a = await get("alpha");
    if (!sodium.crypto_core_ristretto255_is_valid_point(a)) {
      console.debug("Authentication failed.  Alpha is not a group element.");
      give("authenticated", false);
      throw new Error("Authentication failed.  Alpha is not a group element.");
    }
    const xs = sodium.crypto_core_ristretto255_scalar_random();
    const b = util.oprfRaise(a, pepper.ks);
    const Xs = sodium.crypto_scalarmult_ristretto255_base(xs);

    const Xu = await get("Xu");
    const K = util.KE(pepper.ps, xs, pepper.Pu, Xu, Xs);
    const SK = util.oprfF(K, util.sodiumFromByte(0));
    const As = util.oprfF(K, util.sodiumFromByte(1));
    const Au = util.oprfF(K, util.sodiumFromByte(2));

    give("beta", b);
    give("Xs", Xs);
    give("c", pepper.c);
    give("As", As);

    const __Au = await get("Au");
    if (sodium.compare(Au, __Au) === 0) {
      // The comparable value of 0 means equality
      give("authenticated", true);
      const token = sodium.to_hex(SK);
      return token;
    } else {
      console.debug("Authentication failed.  Wrong password for " + user_id);
      give("authenticated", false);
      throw new Error("Authentication failed.  Wrong password for " + user_id);
    }
  };

  return {
    clientRegister,
    serverRegister,
    clientAuthenticate,
    serverAuthenticate,
  };
};
