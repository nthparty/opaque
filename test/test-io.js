/*
 *  Client-Server Communications
 */
const listeners = {};
const mailbox = {};
const dummy_socket = computation_id => ({
  get: (op_id, tag) => {
    return new Promise(function (resolve) {
      tag = computation_id + ':' + op_id + ':' + tag;
      if (mailbox[tag] == null) {
        // console.log('io.get', tag, 'not ready');
        listeners[tag] = resolve;
      } else {
        // console.log('io.get', tag, mailbox[tag]);
        resolve(mailbox[tag]);
        mailbox[tag] = undefined;
      }
    });
  },
  give: (op_id, tag, msg) => {
    tag = computation_id + ':' + op_id + ':' + tag;
    // console.log('io.give', tag, msg);
    if (listeners[tag] == null) {
      mailbox[tag] = msg;
    } else {
      listeners[tag](msg);
      listeners[tag] = undefined;
    }
  },
  listen: (get, tag, callback, op_id) => {
    get = get.bind(null, op_id);
    (function thunk(f) {
      get(tag).then(function (msg) {
        f(msg);
        thunk(f);
      });
    }(callback));
  }
});

module.exports = dummy_socket('example');
