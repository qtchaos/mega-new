/*
  Functions for handling keys. Some ported from the webclient source code, but highly modified.

  mega.nz - https://github.com/meganz/webclient
*/

import { ultimate } from "./common";
import { crypto_encodeprivkey, crypto_encodepubkey } from "./crypto";
import { crypto_rsagenkey, encrypt_key } from "./js/crypto";
import { u_k_aes } from "./security";
import { a32_to_base64, api, base64urlencode, str_to_a32 } from "./utils";

export async function init_key(): Promise<string> {
  return (await crypto_rsagenkey()) as string;
}

export async function u_setrsa(rsakey: any) {
  var privateKeyEncoded = crypto_encodeprivkey(rsakey);
  var publicKeyEncodedB64 = base64urlencode(crypto_encodepubkey(rsakey));

  var request = {
    a: "up",
    privk: a32_to_base64(encrypt_key(u_k_aes, str_to_a32(privateKeyEncoded))),
    pubk: publicKeyEncodedB64,
  };
  const res = await api(ultimate, { body: JSON.stringify(request) });
  return res;
}

export function deriveKey(
  saltBytes: Uint8Array,
  passwordBytes: Uint8Array,
  iterations: number,
  derivedKeyLength: number
): Promise<Uint8Array> {
  return deriveKeyWithWebCrypto(
    saltBytes,
    passwordBytes,
    iterations,
    derivedKeyLength
  );
}

async function deriveKeyWithWebCrypto(
  saltBytes: Uint8Array,
  passwordBytes: Uint8Array,
  iterations: number,
  derivedKeyLength: number
) {
  // Import the password as the key
  const key = await crypto.subtle.importKey(
    "raw",
    passwordBytes,
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  // Required PBKDF2 parameters
  var params = {
    name: "PBKDF2",
    hash: "SHA-512", // mismatch between this hash function and the one used to generate keys, might be an issue?
    salt: saltBytes,
    iterations: iterations,
  };

  const derivedKeyArrayBuffer = await crypto.subtle.deriveBits(
    params,
    key,
    derivedKeyLength
  );
  return new Uint8Array(derivedKeyArrayBuffer);
}
