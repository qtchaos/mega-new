export type RawAccount = {
  firstName: string;
  lastName: string;
  email: string;
  password: string;
};

export type Stage2 = {
  tsid: string;
  k: string;
  u: string;
  ach: number;
};

export type Stage3 = {
  u: string;
  s: number;
  since: number;
  na: number;
  n: number;
  k: string;
  c: number;
  ts: string;
  flags: {
    ach: number;
    mcs: number;
    mfae: number;
    nsre: number;
    nlfe: number;
    cspe: number;
    smsve: number;
    sra: string;
    refpr: number;
    ssrs: number;
    aplvp: number;
    nobp: number;
    rw: number;
    ab_apmap: number;
    ab_nbusp: number;
    ab_dbbuc: number;
    pf: number;
  };
  aav: number;
  ipcc: string;
  ut: string; // Used in the next stage
};

export type Stage4 = {
  ph: string; // Used in the next stage
  m: string;
};

export type Stage5 = {
  s: number;
  at: string;
  msd: number;
  fa: string;
};

export type Stage6 = {
  0: string;
  1: Array<any>;
};

export type KeyStage1 = {
  0: string;
  1: string[];
  /*
  keyStage1[1] = {
    name: base64urldecode(name),
    email: base64urldecode(email),
    result
  }
  */
};

export type KeyStage2 = {
  s: string;
  v: number;
};

export type KeyStage3 = {
  0: string;
  1: string;
};

export type KeyStage4 = {
  u: string;
  s: number;
  since: number;
  na: number;
  email: string;
  emails: string[];
  pemails: any[];
  name: string;
  k: string;
  c: number;
  pubk: string;
  privk: string;
  "^!lang": string;
  ts: string;
  flags: {
    ach: number;
    mcs: number;
    mfae: number;
    nsre: number;
    nlfe: number;
    cspe: number;
    smsve: number;
    sra: string;
    refpr: number;
    ssrs: number;
    aplvp: number;
    nobp: number;
    rw: number;
    ab_nbusp: number;
    ab_dbbuc: number;
    ab_wdns: number;
    pf: number;
  };
  aav: number;
  ipcc: string;
  aas: string;
};
