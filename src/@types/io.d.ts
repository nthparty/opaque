interface IOData {
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

type Tag = keyof IOData;

interface IO {
  get: (op_id: string | undefined, tag: Tag) => Promise<IOData[typeof tag]>;
  give: (op_id: string | undefined, tag: Tag, msg: IOData[typeof tag]) => string;
}
