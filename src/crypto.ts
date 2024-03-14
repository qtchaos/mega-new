/*
  crypto_*
  
  mega.nz - https://github.com/meganz/webclient
*/

export function crypto_encodeprivkey(privk: any) {
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

export function crypto_encodepubkey(pubkey: string[]) {
  var mlen = pubkey[0].length * 8,
    elen = pubkey[1].length * 8;

  return (
    String.fromCharCode(mlen / 256) +
    String.fromCharCode(mlen % 256) +
    pubkey[0] +
    String.fromCharCode(elen / 256) +
    String.fromCharCode(elen % 256) +
    pubkey[1]
  );
}

export function crypto_decodepubkey(pubk: string) {
  var pubkey = [];

  var keylen = pubk.charCodeAt(0) * 256 + pubk.charCodeAt(1);

  // decompose public key
  for (var i = 0; i < 2; i++) {
    if (pubk.length < 2) {
      break;
    }

    var l = (pubk.charCodeAt(0) * 256 + pubk.charCodeAt(1) + 7) >> 3;
    if (l > pubk.length - 2) {
      break;
    }

    pubkey[i] = pubk.substr(2, l);
    pubk = pubk.substr(l + 2);
  }

  // check format
  if (i !== 2 || pubk.length >= 16) {
    return false;
  }

  pubkey[2] = keylen;

  return pubkey;
}
