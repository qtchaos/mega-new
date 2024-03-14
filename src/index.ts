import { startRegistration, api_createuser, startLogin } from "./security";
import {
  createUrl,
  api,
  getEmailConfirmation,
  generatePassword,
} from "./utils";
import {
  KeyStage1,
  KeyStage2,
  KeyStage4,
  RawAccount,
  Stage2,
  Stage3,
  Stage4,
  Stage5,
} from "./types";
import { setUltimate } from "./common";
import Mailjs from "@cemalgnlts/mailjs";

let ph, sid, ut, user, ultimateUrl: string;

async function generateAccount(raw: RawAccount) {
  // 1: Get user
  user = (await api_createuser())[1];

  // 2: Get sid
  const stage2Url = createUrl();
  const stage2 = await api<Stage2>(stage2Url.toString(), {
    body: JSON.stringify({ a: "us", user: user }),
  });
  sid = stage2.tsid;
  // k = stage2.k; // -> used in Stage 6

  // 3: get `ut`
  const stage3Url = createUrl(true, sid);
  const stage3 = await api<Stage3>(stage3Url.toString(), {
    body: JSON.stringify({ a: "ug" }),
  });
  ut = stage3.ut;

  // 4: Get `ph`
  ultimateUrl = createUrl(true, sid, ut).toString();
  setUltimate(ultimateUrl);
  const stage4 = await api<Stage4>(ultimateUrl, {
    body: JSON.stringify({ a: "wpdf" }),
  });
  ph = stage4.ph;

  // 5: Get `a`
  const stage5 = await api<Stage5>(ultimateUrl, {
    body: JSON.stringify({ a: "g", p: ph }),
  });
  // a = stage5.at; // -> used in Stage 6

  // 6: Might not be needed?
  // const stage6 = await api<Stage6>(ultimateUrl.toString(), {
  //   body: JSON.stringify({
  //     a: "p",
  //     i: "TODO", // https://github.com/meganz/webclient/blob/5e9354f184009172f534d9f22bde4b02e93dedc8/js/crypto.js#L2441
  //     n: [
  //       {
  //         a,
  //         k,
  //         ph,
  //         t: 0,
  //       },
  //     ],
  //   }),
  // });

  // Start registration
  const account = await startRegistration(
    raw.firstName,
    raw.lastName,
    raw.email,
    raw.password
  );

  const finalStageUrl = createUrl(false, sid, ut);
  const response = await api<number>(finalStageUrl.toString(), {
    body: JSON.stringify(account),
  });

  return response === 0;
}

async function setupKeys(
  account: RawAccount,
  timeout = 100,
  emailConfirmation: string
) {
  // 0: Wait for server to be ready
  await new Promise((_) => setTimeout(_, timeout));

  // 1: Send confirmation code to the API
  await api<KeyStage1>(ultimateUrl, {
    body: JSON.stringify({ a: "ud2", c: emailConfirmation }),
  });

  // console.log("Stage 1 (confirmation code):", emailConfirmation);

  // 2: Get salt to be used in the next step
  const stage2 = await getSalt();
  async function getSalt() {
    ``;
    const z = await api<KeyStage2>(ultimateUrl, {
      body: JSON.stringify({ a: "us0", user: account.email }),
    });

    // If the request failed, retry with a longer timeout
    if (!z.s || z.v == 1) {
      await getSalt();
    }
    return z;
  }

  // console.log("Stage 2 (salt):", stage2.s);

  // 3: Start the login process, which includes generating RSA keys for the account
  await startLogin(account.email, account.password, stage2.s);

  // console.log("Stage 3 (keys):", k);

  // 4: Get data from api
  // NOTE: not sure if this is really necessary, but
  await api<KeyStage4>(ultimateUrl, {
    body: JSON.stringify({ a: "ug" }),
  });
}

async function test() {
  const mailjs = new Mailjs();
  const mailAccount = await mailjs.createOneAccount();
  const account: RawAccount = {
    firstName: "John",
    lastName: "Doe",
    email: mailAccount.data.username,
    password: generatePassword(),
  };

  console.log("Account:", account.email, account.password);
  console.time("Total");

  // 1: Register account and send email confirmation
  console.time("Registration");
  await generateAccount(account).catch((error) => console.error(error));
  console.timeEnd("Registration");

  // 2: Get email confirmation id -> used in step 3
  console.time("Email");
  const e = await getEmailConfirmation({
    ...mailAccount.data,
  });
  console.log("Email confirmation:", e.url);
  console.timeEnd("Email");

  // 3: Setup keys for account
  // TODO: Send & generate keyrings
  console.time("Keys");
  await setupKeys(account, undefined, e.id).catch((error) =>
    console.error(error)
  );
  console.timeEnd("Keys");
  console.timeEnd("Total");
}

test();
