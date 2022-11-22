import type { IO, IOData, IOValue, Tag } from "../src/types/io"

/*
 *  Client-Server Communications
 */
const listeners: Record<string, (val: IOValue) => void> = {};
const mailbox: Record<string, IOValue> = {};
const dummy_socket = (computation_id: string): IO => ({
  get: (op_id, tag) => {
    return new Promise(function (resolve) {
      const _tag = computation_id + ':' + op_id + ':' + tag;
      const mail = mailbox[_tag] as IOData[typeof tag] | undefined; // TODO: Factor these assertions out
      if (!mail) {
        // console.debug('io.get', _tag, 'not ready');
        listeners[_tag] = resolve as (val: IOValue) => void; // TODO: Factor these assertions out
      } else {
        // console.debug('io.get', _tag, mail);
        resolve(mail);
        delete mailbox[_tag];
      }
    });
  },
  give: (op_id, tag: Tag, msg: IOValue) => {
    const _tag = computation_id + ':' + op_id + ':' + tag;
    // console.debug('io.give', _tag, msg);
    const listener = listeners[_tag];
    if (!listener) {
      mailbox[_tag] = msg;
    } else {
      listener(msg);
      delete listeners[_tag];
    }
  },
});

export = dummy_socket('example');
