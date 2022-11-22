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
  server_oprf_key: Uint8Array;
  secret_server_scalar: Uint8Array;
  public_server_point: Uint8Array;
  public_user_point: Uint8Array;
  asymmetric_keys_enc: AsymmetricKeysEncrypted;
}

export interface AsymmetricKeysEncrypted {
  secret_user_scalar_enc: Ciphertext;
  public_user_point_enc: Ciphertext;
  public_server_point_enc: Ciphertext;
}

export interface Ciphertext {
  mac_tag: Uint8Array;
  body: Uint8Array;
}
