export interface Opaque {
  /**
   * Sign up as a new user
   */
  clientRegister: (password: string, user_id: string, op_id?: string) => Promise<boolean>;

  /**
   * Register a new user for the first time
   */
  serverRegister: (t?: number, op_id?: string) => Promise<UserRecord>;

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

export interface UserRecord {
  id: string;
  pepper: Pepper;
}

export interface Pepper {
  ks: Uint8Array;
  ps: Uint8Array;
  Ps: Uint8Array;
  Pu: Uint8Array;
  c: C;
}

export interface C {
  pu: Ciphertext;
  Pu: Ciphertext;
  Ps: Ciphertext;
}

export interface Ciphertext {
  mac_tag: Uint8Array;
  body: Uint8Array;
}
