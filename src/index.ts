import type { IO } from "./types/io";
import type { Opaque } from "./types/local";
import OPRFSlim from "oprf";
import opaqueFactory from "./lib/opaque";
// import sodium from "libsodium-wrappers-sumo";
// const __sodium = sodium;

export = async (io: IO, sodium?: null | typeof import("libsodium-wrappers-sumo")): Promise<Opaque> => {
  if (sodium == null) {
    sodium = await import("libsodium-wrappers-sumo");//__sodium;//require('libsodium-wrappers-sumo');
  }

  const oprf = new OPRFSlim();//sodium);
  const opaque = opaqueFactory(io, oprf.sodium, oprf);

  await oprf.ready;
  return opaque;
};
