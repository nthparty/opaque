import type { C } from "./local";

export interface IOData {
  sid: string;
  pw: Uint8Array;
  registered: boolean;
  authenticated: boolean;
  client_authenticated: boolean;
  alpha: Uint8Array;
  beta: Uint8Array;
  c: C;
  Xu: Uint8Array;
  Xs: Uint8Array;
  As: Uint8Array;
  Au: Uint8Array;
}

export type Tag = keyof IOData;
export type IOValue = IOData[Tag];

export interface IO {
  get: <T extends Tag>(op_id: string | undefined, tag: T) => Promise<IOData[T]>;
  give: <T extends Tag>(op_id: string | undefined, tag: T, msg: IOData[T]) => void;
}
