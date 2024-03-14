import { base64urldecode } from "./security";

export async function crypto_rsagenkey2() {
  var ko = await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: { name: "SHA-256" },
    },
    true,
    ["sign", "verify"]
  );

  ko = await crypto.subtle.exportKey("jwk", ko.privateKey);
  delete ko.key_ops;
  delete ko.kty;
  delete ko.ext;
  delete ko.alg;

  const ko2 = [ko.n, ko.e, ko.d, ko.p, ko.q, ko.dp, ko.dq, ko.qi];

  var jwk = bytes_to_string(new Uint8Array(ko2));
  console.log(ko2);
  ["n", "e", "d", "p", "q", "dp", "dq", "qi"].map(function (x) {
    return jwk[x];
  });
  return jwk;
}

function bytes_to_string(bytes, utf8 = false) {
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
