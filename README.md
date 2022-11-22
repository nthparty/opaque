# OPAQUE.js
TypeScript implementation of the OPAQUE asymmetric PAKE (aPAKE) protocol

## Protocol
Implementation of [this Internet Draft proposal](https://datatracker.ietf.org/doc/draft-krawczyk-cfrg-opaque).
<!-- https://eprint.iacr.org/2018/163.pdf -->

<!-- https://link.springer.com/content/pdf/10.1007%2F11535218_33.pdf -->
<!-- https://eprint.iacr.org/2005/176.pdf -->

<!-- cite _ -->

<!-- ## Project Layout

    ├─ lib/
    │  ├─ ot.js
    │  ├─ util.js
    │  └─ crypto.js
    ├─ index.js
    └─ src/
       ├─ example.js
       ├─ io-example.js
       ├─ io-template.js
       └─ ascii.js -->

## Installation

You may also install this module from [npm](https://www.npmjs.com/package/@nthparty/opaque).

```shell
npm install @nthparty/opaque
```

## Calling the API

The process generally works as follows:

```javascript
// Each party includes the 1-out-of-n module with IO:
const OT = require('@nthparty/opaque')(IO);

// Login credentials never reaches the server in plaintext
const user_id = 'newuser';
const password = 'correct horse battery staple';

// Sign up
OPAQUE.client_register(password, user_id).then(console.debug.bind(null, 'Registered:'));

// Log in for the first time and receive a session token
OPAQUE.client_authenticate(password, user_id).then(console.debug.bind(null, 'Shared secret:'));

// Register a new user
let user = OPAQUE.server_register();

// Handle a login attempt
OPAQUE.server_authenticate(user.id, user.pepper);

// Result:
'Registered: true'
'Login for newuser succeeded with: 4ccdf3b8cacf08273a085c952aaf3ee83633e6afcedf4f86c00497e862f43c78'
'Shared secret: 4ccdf3b8cacf08273a085c952aaf3ee83633e6afcedf4f86c00497e862f43c78'
```

Please read [opaque.test.ts](https://github.com/nthparty/opaque/blob/main/test/opaque.test.ts) for a more detailed example, and run `npm test` to test it (requires `npm ci -also=dev` first to install dependencies).
