module.exports = (io, sodium) => {
  if (sodium == null) {
    sodium = require('libsodium-wrappers-sumo');
  }

  const OPRF = require('oprf');
  const oprf = new OPRF(sodium);
  const opaque = require('./lib/opaque.js')(io, sodium, oprf);

  return new Promise(async (resolve) => {
    await oprf.ready;
    resolve(opaque);
  });
};
