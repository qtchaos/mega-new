/*
  Functions related to the security of the user's account

  Original source from the meganz webclient, but heavily modified to work with the codebase.

  mega.nz - https://github.com/meganz/webclient
*/

import AES from "./js/sjcl";
import { basePath, ultimate } from "./common";
import {
  getIdWithSeed,
  api,
  stringToByteArray,
  a32_to_str,
  base64urlencode,
  a32_to_base64,
  rand,
  base64_to_a32,
  ab_to_base64,
  base64_to_ab,
  to8,
} from "./utils";
import { decrypt_key, encrypt_key } from "./js/crypto";
import { deriveKey, init_key } from "./key";

/** The number of iterations for the PPF (1-2 secs computation time) */
const numOfIterations = 100000;

/** The length of the salt in bits */
const saltLengthInBits = 128; // 16 Bytes

/** The desired length of the derived key from the PPF in bits */
const derivedKeyLengthInBits = 256; // 32 Bytes

type UC2 = {
  a: "uc2";
  n: string; // Name (used just for the email)
  m: string; // Email
  crv: string; // Client Random Value
  k: string; // Encrypted Master Key
  hak: string; // Hashed Authentication Key
  v: 2; // Version of this protocol
};

export let u_k: Int32Array | Uint32Array = create_u_k();
export let u_sid: string, u_k_aes: AES, u_storage: any, u_privk: any;

export async function startLogin(
  email: string,
  password: string,
  salt: string
) {
  // Convert the salt and password to byte arrays
  var saltArrayBuffer = base64_to_ab(salt);
  var saltBytes = new Uint8Array(saltArrayBuffer);
  var passwordBytes = stringToByteArray(password);

  // The number of iterations for the PPF and desired length in bits of the derived key
  var iterations = numOfIterations;
  var derivedKeyLength = derivedKeyLengthInBits;

  // Run the PPF
  const derivedKeyBytes = await deriveKey(
    saltBytes,
    passwordBytes,
    iterations,
    derivedKeyLength
  );

  // Get the first 16 bytes as the Encryption Key and the next 16 bytes as the Authentication Key
  var derivedEncryptionKeyBytes = derivedKeyBytes.subarray(0, 16);
  var derivedAuthenticationKeyBytes = derivedKeyBytes.subarray(16, 32);
  var authenticationKeyBase64 = ab_to_base64(derivedAuthenticationKeyBytes);

  // Convert the Derived Encryption Key to a big endian array of 32 bit values for decrypting the Master Key
  var derivedEncryptionKeyArray32 = base64_to_a32(
    ab_to_base64(derivedEncryptionKeyBytes)
  );

  // Authenticate with the API
  return await sendAuthenticationKey(
    email,
    authenticationKeyBase64,
    derivedEncryptionKeyArray32
  );
}

async function sendAuthenticationKey(
  email: string,
  authenticationKeyBase64: string,
  derivedEncryptionKeyArray32: any
) {
  // Setup the login request
  var requestVars = { a: "us", user: email, uh: authenticationKeyBase64 };

  // Send the Email and Authentication Key to the API
  const result = await api<{
    tsid: string;
    csid: string;
    k: string;
    privk: string;
    u: string;
  }>(ultimate, {
    body: JSON.stringify(requestVars),
  });

  // Get values from Object
  var temporarySessionIdBase64 = result.tsid;
  // var encryptedSessionIdBase64 = result.csid; // undefined
  var encryptedMasterKeyBase64 = result.k;
  // var encryptedPrivateRsaKey = result.privk; // undefined
  // var userHandle = result.u;

  // Decrypt the Master Key
  var encryptedMasterKeyArray32 = base64_to_a32(encryptedMasterKeyBase64);
  var cipherObject = new AES(derivedEncryptionKeyArray32);
  var decryptedMasterKeyArray32 = decrypt_key(
    cipherObject,
    encryptedMasterKeyArray32
  );

  // If the temporary session ID is set then we need to generate RSA keys
  return await skipToGenerateRsaKeys(
    decryptedMasterKeyArray32,
    temporarySessionIdBase64
  );
}

async function skipToGenerateRsaKeys(
  masterKeyArray32: Int32Array,
  temporarySessionIdBase64: string
) {
  // Set global values which are used everywhere
  u_k = masterKeyArray32;
  u_sid = temporarySessionIdBase64;
  u_k_aes = new AES(masterKeyArray32);

  // Set the Session ID for future API requests
  api_setsid(temporarySessionIdBase64);

  // Redirect to key generation page
  return await init_key();
}

// Sets the Session ID for future API requests
function api_setsid(tsid: string) {
  u_sid = tsid;
}

export async function startRegistration(
  firstName: string,
  lastName: string,
  email: string,
  password: string
) {
  // Derive the Client Random Value, Encrypted Master Key and Hashed Authentication Key
  const {
    clientRandomValueBytes,
    encryptedMasterKeyArray32,
    hashedAuthenticationKeyBytes,
  } = await deriveKeysFromPassword(password, u_k);

  // Encode parameters to Base64 before sending to the API
  const req = {
    a: "uc2",
    n: base64urlencode(to8(firstName + " " + lastName)), // Name (used just for the email)
    m: base64urlencode(to8(email)), // Email
    crv: ab_to_base64(clientRandomValueBytes), // Client Random Value
    k: a32_to_base64(encryptedMasterKeyArray32), // Encrypted Master Key
    hak: ab_to_base64(hashedAuthenticationKeyBytes), // Hashed Authentication Key
    v: 2, // Version of this protocol
  };
  return req as UC2;
}

async function deriveKeysFromPassword(
  password: string,
  masterKeyArray32: Uint32Array | Int32Array
) {
  // Create the 128 bit (16 byte) Client Random Value and Salt
  var saltLengthInBytes = saltLengthInBits / 8;
  var clientRandomValueBytes = crypto.getRandomValues(
    new Uint8Array(saltLengthInBytes)
  );
  var saltBytes = await createSalt(clientRandomValueBytes);

  // Trim the password and convert it from ASCII/UTF-8 to a byte array
  var passwordBytes = stringToByteArray(password);

  // The number of iterations for the PPF and desired length in bits of the derived key
  var iterations = numOfIterations;
  var derivedKeyLength = derivedKeyLengthInBits;

  // Run the PPF
  const derivedKeyBytes: Uint8Array = await deriveKey(
    saltBytes,
    passwordBytes,
    iterations,
    derivedKeyLength
  );

  // Get the first 16 bytes as the Encryption Key and the next 16 bytes as the Authentication Key
  const derivedEncryptionKeyBytes = derivedKeyBytes.subarray(0, 16);
  const derivedAuthenticationKeyBytes = derivedKeyBytes.subarray(16, 32);

  // Get a hash of the Authentication Key which the API will use for authentication at login time
  let hashedAuthenticationKeyBytes = await crypto.subtle.digest(
    "SHA-256",
    derivedAuthenticationKeyBytes
  );

  // Keep only the first 128 bits (16 bytes) of the Hashed Authentication Key
  hashedAuthenticationKeyBytes = new Uint8Array(
    hashedAuthenticationKeyBytes
  ).subarray(0, 16);

  // Convert the Derived Encryption Key to a big endian array of 32 bytes, then encrypt the Master Key
  const derivedEncryptionKeyArray32 = base64_to_a32(
    ab_to_base64(derivedEncryptionKeyBytes)
  );
  const cipherObject = new AES(derivedEncryptionKeyArray32);
  const encryptedMasterKeyArray32 = encrypt_key(cipherObject, masterKeyArray32);

  // Pass the Client Random Value, Encrypted Master Key and Hashed Authentication Key to the calling function
  return {
    clientRandomValueBytes,
    encryptedMasterKeyArray32,
    hashedAuthenticationKeyBytes,
    derivedAuthenticationKeyBytes,
  };
}

// If the user triggers an action that requires an account, but hasn't logged in,
// we create an anonymous preliminary account. Returns userhandle and passwordkey for permanent storage.
export async function api_createuser(
  ctx: { passwordkey: Int32Array | null } = {
    passwordkey: null,
  }
) {
  let i;
  var ssc = Array(4); // session self challenge, will be used to verify password

  if (!ctx.passwordkey) {
    ctx.passwordkey = new Int32Array(4);
    for (i = 4; i--; ) {
      ctx.passwordkey[i] = rand(0x100000000);
    }
  }

  for (i = 4; i--; ) {
    ssc[i] = rand(0x100000000);
  }

  // in business sub-users API team decided to hack "UP" command to include "UC2" new arguments.
  // so now. we will check if this is a business sub-user --> we will add extra arguments to "UP" (crv,hak,v)
  const req = {
    a: "up",
    k: a32_to_base64(encrypt_key(new AES(ctx.passwordkey), u_k)),
    ts: base64urlencode(
      a32_to_str(ssc) + a32_to_str(encrypt_key(new AES(u_k), ssc))
    ),
  };

  const url = new URL(basePath);
  url.pathname = "/cs";
  url.searchParams.append("v", "3");
  url.searchParams.append("id", getIdWithSeed(Math.random()));
  url.searchParams.append("lang", "en");
  url.searchParams.append("domain", "meganz");

  return await api<{ 0: 0; 1: string }>(url.toString(), {
    body: JSON.stringify(req),
  });
}

async function createSalt(
  clientRandomValueBytes: Uint8Array
): Promise<Uint8Array> {
  var saltString = "mega.nz";
  var saltStringMaxLength = 200; // 200 chars for 'mega.nz' + padding
  var saltHashInputLength = saltStringMaxLength + clientRandomValueBytes.length; // 216 bytes

  // Pad the salt string to 200 chars with the letter P
  for (var i = saltString.length; i < saltStringMaxLength; i++) {
    saltString += "P";
  }

  // Cronvert the salt to a byte array
  var saltStringBytes = stringToByteArray(saltString);

  // Concatenate the Client Random Value bytes to the end of the salt string bytes
  var saltInputBytesConcatenated = new Uint8Array(saltHashInputLength);
  saltInputBytesConcatenated.set(saltStringBytes);
  saltInputBytesConcatenated.set(clientRandomValueBytes, saltStringMaxLength);

  // Hash the bytes to create the salt
  var saltBytes = await crypto.subtle.digest(
    "SHA-256",
    saltInputBytesConcatenated
  );

  // Return the salt which is needed for the PPF
  return new Uint8Array(saltBytes);
}

function create_u_k(): Uint32Array {
  // static master key, will be stored at the server side encrypted with the master pw
  return crypto.getRandomValues(new Uint32Array(4));
}
