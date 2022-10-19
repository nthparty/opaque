interface Opaque {
  /**
   * Sign up as a new user
   */
  clientRegister: (password: string, user_id: string, op_id: string) => Promise<boolean>;

  /**
   * Register a new user for the first time
   */
  serverRegister: (t: number | undefined, op_id: string) => Promise<UserRecord>;

  /**
   * Try to log in
   */
  clientAuthenticate: (
    password: string,
    user_id: string,
    t?: number,
    op_id?: string
  ) => Promise<string>;

  /**
   * Authenticate a user
   */
  serverAuthenticate: (user_id: string, pepper: Pepper, op_id?: string) => Promise<string>;
}

interface UserRecord {
  id: string;
  pepper: Pepper;
}

interface Pepper {
  ks: Uint8Array;
  ps: Uint8Array;
  Ps: Uint8Array;
  Pu: Uint8Array;
  c: C;
}

interface C {
  pu: Ciphertext;
  Pu: Ciphertext;
  Ps: Ciphertext;
}

interface Ciphertext {
  mac_tag: Uint8Array;
  body: Uint8Array;
}
