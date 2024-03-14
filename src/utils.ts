/*
  Everything that doesnt fit in any other file goes here.

  mega.nz - https://github.com/meganz/webclient
*/

import { basePath } from "./common";
import Mailjs from "@cemalgnlts/mailjs";

export function getIdWithSeed(seed: number): string {
  return Math.floor(seed * 1000000000).toString();
}

export function createUrl(
  v: boolean = true,
  sid: string = "",
  ut: string = ""
) {
  const url = new URL(basePath);
  url.pathname = "/cs";
  if (v) url.searchParams.append("v", "3");
  url.searchParams.append("id", getIdWithSeed(Math.random()));
  url.searchParams.append("lang", "en");
  url.searchParams.append("domain", "meganz");
  if (sid) url.searchParams.append("sid", sid);
  if (ut) url.searchParams.append("ut", ut);

  return url;
}

export async function api<T>(
  url: string,
  options: RequestInit | undefined,
  json: boolean = true
): Promise<T> {
  if (!options) {
    options = {} as RequestInit;
  }

  options = {
    ...options,
    headers: {
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
      Accept: "*/*",
      "Accept-Language": "en-US,en;q=0.5",
      "Accept-Encoding": "gzip, deflate, br",
      Referer: "https://mega.nz/",
      "Content-Type": "text/plain;charset=UTF-8",
      Host: "g.api.mega.co.nz",
      Origin: "https://mega.nz",
      DNT: "1",
      Connection: "keep-alive",
      "Sec-Fetch-Dest": "empty",
      "Sec-Fetch-Mode": "cors",
      "Sec-Fetch-Site": "cross-site",
      Pragma: "no-cache",
      "Cache-Control": "no-cache",
      ...options.headers,
    },
  };

  if (options.body) options.body = `[${options.body}]`;

  if (!options.method) options.method = "POST";

  const response = await fetch(url, options);
  if (!response.ok) {
    throw new Error(response.statusText);
  }

  if (json) {
    let data = await response.json();
    if (Array.isArray(data)) data = data[0];
    return data as Promise<T>;
  } else {
    return response.text() as Promise<T>;
  }
}

export async function pollForEmail(token: string) {
  const mailjs = new Mailjs();
  mailjs.loginWithToken(token);

  const messages = await mailjs.getMessages();
  if (messages.data.length === 0) {
    await new Promise((resolve) => setTimeout(resolve, 250));
    return pollForEmail(token);
  }
  const msgId = messages.data[0].id;
  const message = await mailjs.getMessage(msgId);
  return message;
}

export async function getEmailConfirmation(emailAccount: {
  username: string;
  password: string;
}): Promise<{ url: string; id: string }> {
  const mailjs = new Mailjs();
  const token = (
    await mailjs.login(emailAccount.username, emailAccount.password)
  ).data.token;

  return await pollForEmail(token).then((messages) => {
    const regex = /https:\/\/mega\.nz\/#confirm[a-zA-Z0-9_-]+/;
    const link = messages.data.text.match(regex);
    if (!link) throw new Error("No confirmation link found.");
    const id = link[0].split("#confirm")[1];
    return { url: link[0], id };
  });
}

export function generatePassword(length: number = 12): string {
  const charset =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let password = "";
  for (let i = 0; i < length; i++) {
    password += charset.charAt(Math.floor(Math.random() * charset.length));
  }
  return password;
}

export function base64_to_a32(s: string): Int32Array {
  return str_to_a32(base64urldecode(s)) as Int32Array;
}

export function base64urldecode(data: string) {
  data += "==".substr((2 - data.length * 3) & 3);

  data = data.replace(/\-/g, "+").replace(/_/g, "/").replace(/,/g, "");

  try {
    return atob(data);
  } catch (e) {
    return "";
  }
}

// binary string to ArrayBuffer, 0-padded to AES block size
export function base64_to_ab(a: string) {
  return str_to_ab(base64urldecode(a));
}

// binary string to ArrayBuffer, 0-padded to AES block size
export function str_to_ab(b: string) {
  var ab = new ArrayBuffer((b.length + 15) & -16);
  var u8 = new Uint8Array(ab);

  for (var i = b.length; i--; ) {
    u8[i] = b.charCodeAt(i);
  }

  return ab;
}

export function stringToByteArray(str: string) {
  return new TextEncoder().encode(str);
}

export function to8(unicode: string) {
  return unescape(encodeURIComponent(unicode));
}

export function base64urlencode(data: string) {
  var b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=";
  var b64a = b64.split("");
  if (typeof btoa === "function") {
    return btoa(data).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
  }

  var o1,
    o2,
    o3,
    h1,
    h2,
    h3,
    h4,
    bits,
    i = 0,
    ac = 0,
    enc = "",
    tmp_arr = [];

  do {
    // pack three octets into four hexets
    o1 = data.charCodeAt(i++);
    o2 = data.charCodeAt(i++);
    o3 = data.charCodeAt(i++);

    bits = (o1 << 16) | (o2 << 8) | o3;

    h1 = (bits >> 18) & 0x3f;
    h2 = (bits >> 12) & 0x3f;
    h3 = (bits >> 6) & 0x3f;
    h4 = bits & 0x3f;

    // use hexets to index into b64, and append result to encoded string
    tmp_arr[ac++] = b64a[h1] + b64a[h2] + b64a[h3] + b64a[h4];
  } while (i < data.length);

  enc = tmp_arr.join("");
  var r = data.length % 3;
  return r ? enc.slice(0, r - 3) : enc;
}

export function ab_to_base64(ab: ArrayBuffer) {
  return base64urlencode(ab_to_str(ab));
}

export function ab_to_str(ab: ArrayBuffer) {
  var b = "",
    i;
  var ab8 = new Uint8Array(ab);

  for (i = 0; i < ab8.length; i++) {
    b = b + String.fromCharCode(ab8[i]);
  }

  return b;
}

export function a32_to_base64(a: Int32Array) {
  return base64urlencode(a32_to_str(a));
}

export function a32_to_str(a: any) {
  var b = "";

  for (var i = 0; i < a.length * 4; i++) {
    b = b + String.fromCharCode((a[i >> 2] >>> (24 - (i & 3) * 8)) & 255);
  }

  return b;
}

// string to array of 32-bit words (big endian)
export function str_to_a32(b: string): Int32Array {
  var a = new Int32Array((b.length + 3) >> 2);
  for (var i = 0; i < b.length; i++) {
    a[i >> 2] |= b.charCodeAt(i) << (24 - (i & 3) * 8);
  }
  return a;
}

// random number between 0 .. n -- based on repeated calls to rc
export function rand(n: number) {
  let r = new Uint32Array(1);
  crypto.getRandomValues(r);
  return r[0] % n;
}
