import {
  startRegistration,
  api_createuser,
  a32_to_base64,
  str_to_a32,
  u_k,
  base64urldecode,
  startLogin,
} from "./security";
import { createUrl, api, getEmailConfirmation } from "./utils";
import {
  KeyStage1,
  KeyStage2,
  KeyStage3,
  KeyStage4,
  RawAccount,
  Stage2,
  Stage3,
  Stage4,
  Stage5,
  Stage6,
} from "./types";
import { setUltimate } from "./common";
import Mailjs from "@cemalgnlts/mailjs";
import { crypto_encodeprivkey, crypto_rsagenkey, encrypt_key } from "./crypto";
import { crypto_rsagenkey2 } from "./crypto2";
import { AES } from "./sjcl";

let ph, sid, ut, k, a, user, ultimateUrl: string;

async function generateAccount(raw: RawAccount) {
  // 1: Get user
  user = (await api_createuser())[1];

  // 2: Get sid
  const stage2Url = createUrl();
  const stage2 = await api<Stage2>(stage2Url.toString(), {
    body: JSON.stringify({ a: "us", user: user }),
  });
  sid = stage2.tsid;
  k = stage2.k;

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
  a = stage5.at;

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

  console.info("Done registering, check your email.");
  return response === 0;
}

async function setupKeys(
  account: RawAccount,
  timeout = 100,
  emailConfirmation: string
) {
  let privk, pubk;

  // 0: Wait for server to be ready
  await new Promise((_) => setTimeout(_, timeout));

  // 1: Send confirmation code to the API
  const stage1 = await api<KeyStage1>(ultimateUrl, {
    body: JSON.stringify({ a: "ud2", c: emailConfirmation }),
  });

  let [name, email, result] = stage1[1];
  name = base64urldecode(name);
  email = base64urldecode(email);
  console.log(name, email, result);
  console.info("Stage 1:", stage1);

  // 2: Get keys
  const stage2 = await fetchStage2();
  async function fetchStage2() {
    const z = await api<KeyStage2>(ultimateUrl, {
      body: JSON.stringify({ a: "us0", user: account.email }),
    });

    // If the request failed, retry with a longer timeout
    if (!z.s || z.v == 1) {
      await fetchStage2();
    }
    return z;
  }

  console.log("Stage 2 (salt):", stage2.s);

  await startLogin(account.email, account.password, stage2.s);

  // 3: Upload keys to api
  const stage3 = await api<KeyStage3>(ultimateUrl, {
    body: JSON.stringify({ a: "up", i: "LH/Dhn$", privk, pubk }),
  });
  console.log("Stage 3:", stage3);

  // if (!stage3[0]) throw new Error("Failed during stage 3 of key setup.");

  // 4: Get data
  const stage4 = await api<KeyStage4>(ultimateUrl, {
    body: JSON.stringify({ a: "ug" }),
  });

  console.log("Stage 4:", stage4);

  return {};
}

async function test() {
  const mailjs = new Mailjs();
  const mailAccount = await mailjs.createOneAccount();
  const account: RawAccount = {
    firstName: "John",
    lastName: "Doe",
    email: mailAccount.data.username,
    password: "semiautomatic",
  };

  const u_k_aes = new AES(u_k);
  const privateKeyEncoded = crypto_encodeprivkey(await crypto_rsagenkey2());
  const privk = a32_to_base64(
    encrypt_key(u_k_aes, str_to_a32(privateKeyEncoded))
  );
  console.log(privk);

  console.time("Total");

  // // 1: Register account and send email confirmation
  console.time("Registration");
  await generateAccount(account).catch((error) => console.error(error));
  console.timeEnd("Registration");

  // // 2: Get email confirmation id -> used in step 3
  console.time("Email");
  const e = await getEmailConfirmation({
    ...mailAccount.data,
  });
  console.log("Email confirmation:", e.url);
  console.timeEnd("Email");

  // // 3: Setup keys for account
  console.time("Keys");
  await setupKeys(account, undefined, e.id).catch((error) =>
    console.error(error)
  );
  console.timeEnd("Keys");
  console.timeEnd("Total");
}

test();
