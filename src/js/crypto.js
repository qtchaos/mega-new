/*
  Contains functions for encrypting and decrypting data using RSA and AES ciphers.

  TODO: Translate to TypeScript  

  mega.nz - https://github.com/meganz/webclient
*/

import { u_setrsa } from "../key";

export function encrypt_key(cipher, a) {
  if (!a) {
    a = [];
  }
  if (!cipher) {
    console.error("No encryption cipher provided!");
    return false;
  }
  if (a.length == 4) {
    return cipher.encrypt(a);
  }
  var x = [];
  for (var i = 0; i < a.length; i += 4) {
    x = x.concat(cipher.encrypt([a[i], a[i + 1], a[i + 2], a[i + 3]]));
  }
  return x;
}

export function decrypt_key(cipher, a) {
  if (!cipher) {
    console.error("No decryption cipher provided!");
    return false;
  }
  if (a.length == 4) {
    return cipher.decrypt(a);
  }

  var x = [];
  for (var i = 0; i < a.length; i += 4) {
    x = x.concat(cipher.decrypt([a[i], a[i + 1], a[i + 2], a[i + 3]]));
  }
  return x;
}

/*
  Very jank translation of what mega.nz uses to generate RSA keys.
  
  This might be completely wrong, but im not familiar enough with RSA to know for sure.
*/
export async function crypto_rsagenkey() {
  var ko = await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: { name: "SHA-256" }, // Mismatch between this and other hashes used in the code, issue with not using msCrypto
    },
    true,
    ["sign", "verify"]
  );

  ko = await crypto.subtle.exportKey("jwk", ko.privateKey);
  delete ko.key_ops;
  delete ko.kty;
  delete ko.ext;
  delete ko.alg;

  return await u_setrsa([ko.n, ko.e, ko.d, ko.p, ko.q, ko.dp, ko.dq, ko.qi]);
}

export function bytes_to_string(bytes, utf8 = false) {
  var len = bytes.length,
    chars = new Array(len);

  for (var i = 0, j = 0; i < len; i++) {
    var b = bytes[i];
    if (!utf8 || b < 128) {
      chars[j++] = b;
    } else if (b >= 192 && b < 224 && i + 1 < len) {
      chars[j++] = ((b & 0x1f) << 6) | (bytes[++i] & 0x3f);
    } else if (b >= 224 && b < 240 && i + 2 < len) {
      chars[j++] =
        ((b & 0xf) << 12) | ((bytes[++i] & 0x3f) << 6) | (bytes[++i] & 0x3f);
    } else if (b >= 240 && b < 248 && i + 3 < len) {
      var c =
        ((b & 7) << 18) |
        ((bytes[++i] & 0x3f) << 12) |
        ((bytes[++i] & 0x3f) << 6) |
        (bytes[++i] & 0x3f);
      if (c <= 0xffff) {
        chars[j++] = c;
      } else {
        c ^= 0x10000;
        chars[j++] = 0xd800 | (c >> 10);
        chars[j++] = 0xdc00 | (c & 0x3ff);
      }
    } else {
      throw new Error("Malformed UTF8 character at byte offset " + i);
    }
  }

  var str = "",
    bs = 16384;
  for (var i = 0; i < j; i += bs) {
    str += String.fromCharCode.apply(
      String,
      chars.slice(i, i + bs <= j ? i + bs : j)
    );
  }

  return str;
}
