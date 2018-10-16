function ecies_encrypt(curve, publicKey, message) {
  const kdfIterations = 1000;
//  const ivSize = 16;
//  const cipherAlgo = 'aes-256-cbc-hmac-sha256';
  const ivSize = 12;
  const cipherAlgo = 'chacha20-poly1305';

  crypto = require('crypto');

  // Size vary with key size
  // Generate IV
  const iv = crypto.randomBytes(ivSize);

  // Generate Shared Secret
  const ecdh = crypto.createECDH(curve);
  ecdh.generateKeys();
  const shared_secret = ecdh.computeSecret(publicKey, 'base64', 'base64');

  // Derivate Secret
  // - Salt >= 16bytes
  // - Higher iterations
  // - Size = 2 * IV
  const d_shared_secret = crypto.pbkdf2Sync(shared_secret, iv, kdfIterations, 32, 'sha256'); 

  // Cipher Message
  const cipher = crypto.createCipheriv(cipherAlgo, d_shared_secret, iv);
  let encrypted_message = cipher.update(message, 'utf-8', 'base64');
  encrypted_message += cipher.final('base64');

  const hmac = null;

  return [curve, encrypted_message, iv.toString('base64'), ecdh.getPublicKey('base64', 'compressed'), hmac].join('|');
}

function ecies_decrypt(privateKey, payload) {
  const kdfIterations = 1000;
//  const cipherAlgo = 'aes-256-cbc-hmac-sha256';
  const cipherAlgo = 'chacha20-poly1305';

  crypto = require('crypto');

  // TODO validate length
  var [curve, encrypted_message, ivBase64, publicKey, hmac] = payload.split('|');

  const iv = Buffer.from(ivBase64, 'base64');

  // Generate Shared Secret
  const ecdh = crypto.createECDH(curve);
  ecdh.setPrivateKey(privateKey, 'base64', 'base64');
  const shared_secret = ecdh.computeSecret(publicKey, 'base64', 'base64');

  // Derivate Secret
  // - Salt >= 16bytes
  // - Higher iterations
  // - Size = 2 * IV
  const d_shared_secret = crypto.pbkdf2Sync(shared_secret, iv, kdfIterations, 32, 'sha256'); 
  
  // Cipher Message
  const decipher = crypto.createDecipheriv(cipherAlgo, d_shared_secret, iv);
  let message = decipher.update(encrypted_message, 'base64', 'utf-8');
  message += decipher.final('utf-8');

  return message;
}


crypto = require('crypto');

//console.log(crypto.getCiphers());

const C_CURVE = 'brainpoolP256t1';
/*
// Generate Bob keys
const ecdh_bob = crypto.createECDH(C_CURVE);
ecdh_bob.generateKeys();
const bob_priv = ecdh_bob.getPrivateKey('base64', 'compressed');
const bob_pub = ecdh_bob.getPublicKey('base64', 'compressed');
console.log("Priv " + bob_priv);
console.log("Pub " + bob_pub);

for (var i=0; i < 50; i++) {
  payload = ecies_encrypt(C_CURVE, bob_pub, 'yourmom');
  console.log(payload);
  console.log(ecies_decrypt(bob_priv, payload));
}
*/

//-------------------------------------------------------------

// https://tools.ietf.org/html/rfc5869
function hkdf(len, ikm, salt, info) {
  const hmacAlgo = 'sha256';
  crypto = require('crypto');

  var hashLen = Buffer.byteLength(salt);
  if (hashLen == 0) {
    hashLen = Buffer.byteLength(ikm);
    salt = Buffer.alloc(hashLen);
  }

  // Extract
  var prk = crypto.createHmac(hmacAlgo, salt)
    .update(ikm)
    .digest();

  console.debug("PRK=" + prk.toString('hex'));

  var okm = Buffer.from("");
  var t = Buffer.from("");
  for (var i=0; i < Math.ceil(len / hashLen); i++) {
    t = crypto.createHmac(hmacAlgo, prk)
        .update(Buffer.concat([t, info, Buffer.from([i+1])]))
        .digest();
    // Expand
    okm = Buffer.concat([okm, t]);
    if (hashLen == 0) break;
  }

  return okm.slice(0, len);
}


var test_vectors = [
  {
    ikm : "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
    salt: "000102030405060708090a0b0c",
    info: "f0f1f2f3f4f5f6f7f8f9",
    len: 42,
    okm: "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
  },
  {
    ikm : "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
    salt: "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
    info: "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
    len: 82,
    okm: "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87"
  },
  {
    ikm : "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
    salt: "",
    info: "",
    len: 42,
    okm: "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
  }
];

for (var i=0; i < test_vectors.length; i++) {
  var test_vector = test_vectors[i];
  var result = hkdf(test_vector.len,
    Buffer.from(test_vector.ikm, "hex"),
    Buffer.from(test_vector.salt, "hex"),
    Buffer.from(test_vector.info, "hex"));
  console.log((i+1) + " OKM=" + result.toString('hex') + " - " + (result.toString('hex') == test_vector.okm));
}
return;
