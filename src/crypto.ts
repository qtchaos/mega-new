import { base64urldecode } from "./security";
import { AES } from "./sjcl";

// export async function crypto_rsagenkey2(): Promise<string[]> {
//   var ko = await crypto.subtle.generateKey(
//     {
//       name: "RSAES-PKCS1-v1_5",
//       modulusLength: 2048,
//       publicExponent: new Uint8Array([1, 0, 1]),
//       hash: { name: "SHA-256" },
//     },
//     true,
//     ["encrypt", "decrypt"]
//   );

//   ko = await crypto.subtle.exportKey("jwk", ko.privateKey);
//   var jwk = JSON.parse(bytes_to_string(new Uint8Array(ko)));
//   ["n", "e", "d", "p", "q", "dp", "dq", "qi"].map(function (x) {
//     return base64urldecode(jwk[x]);
//   });
//   return ko;
// }

export async function crypto_rsagenkey(): Promise<string[]> {
  const ko = await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: { name: "SHA-256" },
    },
    true,
    ["verify", "sign"]
  );

  let jwk = await crypto.subtle.exportKey("jwk", ko.privateKey);
  delete jwk.key_ops;
  delete jwk.kty;
  delete jwk.ext;
  delete jwk.alg;

  const privk: string[] = ["n", "e", "d", "p", "q", "dp", "dq", "qi"].map(
    (x) => (jwk as { [key: string]: any })[x]
  );

  return privk;
}

// encrypt/decrypt 4- or 8-element 32-bit integer array
export function encrypt_key(cipher: AES, a: Int32Array): Int32Array {
  if (a.length == 4) {
    return cipher.encrypt(a);
  }
  var x: any[] = [];
  for (var i = 0; i < a.length; i += 4) {
    let int32Array = new Int32Array([a[i], a[i + 1], a[i + 2], a[i + 3]]);
    x = x.concat(cipher.encrypt(int32Array));
  }
  return x as unknown as Int32Array;
}

export function decrypt_key(cipher: AES, a: Int32Array): Int32Array {
  if (a.length == 4) {
    return cipher.decrypt(a);
  }

  var x: any[] = [];
  for (var i = 0; i < a.length; i += 4) {
    let int32Array = new Int32Array([a[i], a[i + 1], a[i + 2], a[i + 3]]);
    x = x.concat(cipher.decrypt(int32Array));
  }
  return x as unknown as Int32Array;
}

export function crypto_encodeprivkey(privk: any) {
  console.log(privk);
  var plen = privk[3].length * 8,
    qlen = privk[4].length * 8,
    dlen = privk[2].length * 8,
    ulen = privk[7].length * 8;

  var t =
    String.fromCharCode(qlen / 256) +
    String.fromCharCode(qlen % 256) +
    privk[4] +
    String.fromCharCode(plen / 256) +
    String.fromCharCode(plen % 256) +
    privk[3] +
    String.fromCharCode(dlen / 256) +
    String.fromCharCode(dlen % 256) +
    privk[2] +
    String.fromCharCode(ulen / 256) +
    String.fromCharCode(ulen % 256) +
    privk[7];

  while (t.length & 15)
    t += String.fromCharCode(Math.floor(Math.random() * 256));

  return t;
}

function bytes_to_string(bytes: Uint8Array, utf8: boolean = false): string {
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
