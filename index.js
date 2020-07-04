module.exports = function (io, sodium) {
  if (sodium == null) {
    sodium = require('libsodium-wrappers-sumo');
  }

  const OPRF = require('oprf');
  const oprf = new OPRF(sodium);
  const opaque = require('./lib/opaque.js')(io, sodium, oprf);

  return new Promise(function (resolve) {
    oprf.ready.then(function () {
      resolve(opaque);
    });
  });
};
