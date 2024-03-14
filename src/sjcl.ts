/** @fileOverview Javascript cryptography implementation.
 *
 * Crush to remove comments, shorten variable names and
 * generally reduce transmission size.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 *
 * Version 1.0.3
 */

/*jslint indent: 2, bitwise: false, nomen: false, plusplus: false, white: false, regexp: false */
/*global document, window, escape, unescape, module, require, Uint32Array */

/** @namespace The Stanford Javascript Crypto Library, top-level namespace. */

interface Exception {
  message: string;
  toString: () => string;
}

interface Exceptions {
  corrupt: (message: string) => Exception;
  invalid: (message: string) => Exception;
  bug: (message: string) => Exception;
  notReady: (message: string) => Exception;
}

let exceptions: Exceptions = {
  corrupt: function (message: string): Exception {
    return {
      message,
      toString: function () {
        return "CORRUPT: " + this.message;
      },
    };
  },
  invalid: function (message: string): Exception {
    return {
      message,
      toString: function () {
        return "INVALID: " + this.message;
      },
    };
  },
  bug: function (message: string): Exception {
    return {
      message,
      toString: function () {
        return "BUG: " + this.message;
      },
    };
  },
  notReady: function (message: string): Exception {
    return {
      message,
      toString: function () {
        return "NOT READY: " + this.message;
      },
    };
  },
};

/** @fileOverview Low-level AES implementation.
 *
 * This file contains a low-level implementation of AES, optimized for
 * size and for efficiency on several browsers.  It is based on
 * OpenSSL's aes_core.c, a public-domain implementation by Vincent
 * Rijmen, Antoon Bosselaers and Paulo Barreto.
 *
 * An older version of this implementation is available in the public
 * domain, but this one is (c) Emily Stark, Mike Hamburg, Dan Boneh,
 * Stanford University 2008-2010 and BSD-licensed for liability
 * reasons.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */

/**
 * Schedule out an AES key for both encryption and decryption.  This
 * is a low-level class.  Use a cipher mode to do bulk encryption.
 *
 * @constructor
 * @param {Array} key The key as an array of 4, 6 or 8 words.
 *
 * @class Advanced Encryption Standard (low-level interface)
 */
export class AES {
  _tables: number[][][];
  _key: Int32Array | Uint32Array;
  constructor(key: Int32Array | Uint32Array) {
    this._tables = [
      [[], [], [], [], []],
      [[], [], [], [], []],
    ];

    if (!this._tables[0][0][0]) {
      this._precompute();
    }

    let i,
      j,
      tmp,
      encKey: Int32Array | Uint32Array,
      decKey = [],
      sbox = this._tables[0][4],
      decTable = this._tables[1],
      keyLen = key.length,
      rcon = 1;

    if (keyLen !== 4 && keyLen !== 6 && keyLen !== 8) {
      throw exceptions.invalid("invalid aes key size");
    }

    this._key = [(encKey = key.slice(0))];

    // schedule encryption keys
    for (i = keyLen; i < 4 * keyLen + 28; i++) {
      tmp = encKey[i - 1];

      // apply sbox
      if (i % keyLen === 0 || (keyLen === 8 && i % keyLen === 4)) {
        tmp =
          (sbox[tmp >>> 24] << 24) ^
          (sbox[(tmp >> 16) & 255] << 16) ^
          (sbox[(tmp >> 8) & 255] << 8) ^
          sbox[tmp & 255];

        // shift rows and add rcon
        if (i % keyLen === 0) {
          tmp = (tmp << 8) ^ (tmp >>> 24) ^ (rcon << 24);
          rcon = (rcon << 1) ^ ((rcon >> 7) * 283);
        }
      }

      encKey[i] = encKey[i - keyLen] ^ tmp;
    }

    // schedule decryption keys
    for (j = 0; i; j++, i--) {
      tmp = encKey[j & 3 ? i : i - 4];
      if (i <= 4 || j < 4) {
        decKey[j] = tmp;
      } else {
        decKey[j] =
          decTable[0][sbox[tmp >>> 24]] ^
          decTable[1][sbox[(tmp >> 16) & 255]] ^
          decTable[2][sbox[(tmp >> 8) & 255]] ^
          decTable[3][sbox[tmp & 255]];
      }
    }
  }

  /**
   * Encrypt an array of 4 big-endian words.
   * @param {Array} data The plaintext.
   * @return {Array} The ciphertext.
   */
  encrypt = (data: Int32Array): Int32Array => {
    return this._crypt(data, 0);
  };

  /**
   * Decrypt an array of 4 big-endian words.
   * @param {Array} data The ciphertext.
   * @return {Array} The plaintext.
   */
  decrypt = (data: Int32Array): Int32Array => {
    return this._crypt(data, 1);
  };

  /**
   * Expand the S-box tables.
   *
   * @private
   */
  _precompute = () => {
    var encTable = this._tables[0],
      decTable = this._tables[1],
      sbox: number[] = encTable[4],
      sboxInv: number[] = decTable[4],
      i,
      x,
      xInv,
      d = [],
      th = [],
      x2,
      x4,
      x8,
      s,
      tEnc,
      tDec;

    // Compute double and third tables
    for (i = 0; i < 256; i++) {
      th[(d[i] = (i << 1) ^ ((i >> 7) * 283)) ^ i] = i;
    }

    for (x = xInv = 0; !sbox[x]; x ^= x2 || 1, xInv = th[xInv] || 1) {
      // Compute sbox
      s = xInv ^ (xInv << 1) ^ (xInv << 2) ^ (xInv << 3) ^ (xInv << 4);
      s = (s >> 8) ^ (s & 255) ^ 99;
      sbox[x] = s;
      sboxInv[s] = x;

      // Compute MixColumns
      x8 = d[(x4 = d[(x2 = d[x])])];
      tDec = (x8 * 0x1010101) ^ (x4 * 0x10001) ^ (x2 * 0x101) ^ (x * 0x1010100);
      tEnc = (d[s] * 0x101) ^ (s * 0x1010100);

      for (i = 0; i < 4; i++) {
        encTable[i][x] = tEnc = (tEnc << 24) ^ (tEnc >>> 8);
        decTable[i][s] = tDec = (tDec << 24) ^ (tDec >>> 8);
      }
    }

    // Compactify.  Considerable speedup on Firefox.
    for (i = 0; i < 5; i++) {
      encTable[i] = encTable[i].slice(0);
      decTable[i] = decTable[i].slice(0);
    }
  };

  /**
   * Encryption and decryption core.
   * @param {Array} input Four words to be encrypted or decrypted.
   * @param dir The direction, 0 for encrypt and 1 for decrypt.
   * @return {Array} The four encrypted or decrypted words.
   * @private
   */
  _crypt = (input: Int32Array, dir: number): Int32Array => {
    if (input.length !== 4) {
      throw exceptions.invalid("invalid aes block size");
    }

    var key = this._key[dir],
      // state variables a,b,c,d are loaded with pre-whitened data
      a = input[0] ^ key[0],
      b = input[dir ? 3 : 1] ^ key[1],
      c = input[2] ^ key[2],
      d = input[dir ? 1 : 3] ^ key[3],
      a2,
      b2,
      c2,
      nInnerRounds = key.length / 4 - 2,
      i,
      kIndex = 4,
      out: Int32Array = new Int32Array(4),
      table = this._tables[dir],
      // load up the tables
      t0 = table[0],
      t1 = table[1],
      t2 = table[2],
      t3 = table[3],
      sbox = table[4];

    // Inner rounds.  Cribbed from OpenSSL.
    for (i = 0; i < nInnerRounds; i++) {
      a2 =
        t0[a >>> 24] ^
        t1[(b >> 16) & 255] ^
        t2[(c >> 8) & 255] ^
        t3[d & 255] ^
        key[kIndex];
      b2 =
        t0[b >>> 24] ^
        t1[(c >> 16) & 255] ^
        t2[(d >> 8) & 255] ^
        t3[a & 255] ^
        key[kIndex + 1];
      c2 =
        t0[c >>> 24] ^
        t1[(d >> 16) & 255] ^
        t2[(a >> 8) & 255] ^
        t3[b & 255] ^
        key[kIndex + 2];
      d =
        t0[d >>> 24] ^
        t1[(a >> 16) & 255] ^
        t2[(b >> 8) & 255] ^
        t3[c & 255] ^
        key[kIndex + 3];
      kIndex += 4;
      a = a2;
      b = b2;
      c = c2;
    }

    // Last round.
    for (i = 0; i < 4; i++) {
      out[dir ? 3 & -i : i] =
        (sbox[a >>> 24] << 24) ^
        (sbox[(b >> 16) & 255] << 16) ^
        (sbox[(c >> 8) & 255] << 8) ^
        sbox[d & 255] ^
        key[kIndex++];
      a2 = a;
      a = b;
      b = c;
      c = d;
      d = a2;
    }

    return out;
  };
}
