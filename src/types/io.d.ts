import type { AsymmetricKeysEncrypted } from './local';

export interface IOData {
  session_id: string;
  password_digest: Uint8Array;
  registered: boolean;
  authenticated: boolean;
  client_authenticated: boolean;
  alpha: Uint8Array;
  beta: Uint8Array;
  asymmetric_keys_enc: AsymmetricKeysEncrypted;
  ephemeral_public_user_point: Uint8Array;
  ephemeral_public_server_point: Uint8Array;
  server_authentication_token: Uint8Array;
  user_authentication_token: Uint8Array;
}

export type Tag = keyof IOData;
export type IOValue = IOData[Tag];

export interface IO {
  get: <T extends Tag>(op_id: string | undefined, tag: T) => Promise<IOData[T]>;
  give: <T extends Tag>(op_id: string | undefined, tag: T, msg: IOData[T]) => void;
}
