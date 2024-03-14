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
      "User-Agent":
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
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
