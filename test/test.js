/*
 *  This is the setup for authenticated PAKE between a client and server.
 *  In this test, a new user approches the sever and registers an account.
 *  Then the connection is reset, and the user attempts to log in.
 */
var IO = require('./test-io.js');
const OPAQUE = require('../index.js')(IO);

OPAQUE.then(function (OPAQUE) {

  /*
   *  Client
   */
  const user_id = 'newuser';
  const password = 'correct horse battery staple';

  // Sign up
  OPAQUE.client_register(password, user_id).then(console.log.bind(null, 'Registered:'));

  // Log in for the first time and receive a session token
  OPAQUE.client_authenticate(password, user_id).then(console.log.bind(null, 'Shared secret:'));


  /*
   *  Server
   */
  var database = {};  // Test database to show what user data gets stored

  // Register a new user
  OPAQUE.server_register().then(function (user) {
    database[user.id] = user.pepper;

    // Handle a login attempt
    let user_id = user.id;
    let pepper = database[user_id];
    OPAQUE.server_authenticate(user_id, pepper).then(function (token) {
      if (token == null) {
        console.log('Incorrect username or password');
      } else {
        console.log('Login for ' + user_id + ' succeeded with resulting token:', token);
      }
    });
  });

});
