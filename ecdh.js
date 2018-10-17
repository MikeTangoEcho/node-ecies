function ecies_encrypt(curve, publicKey, message) {
  const kdfIterations = 1000;
  const hmacAlgo = 'sha256';
//  const ivSize = 16;
//  const cipherAlgo = 'aes-256-cbc-hmac-sha256';
  const ivSize = 12;
  const cipherAlgo = 'chacha20-poly1305';

  crypto = require('crypto');

  // Size vary with key size
  // Generate IV aka S1
  const iv = crypto.randomBytes(ivSize);
  const s2 = crypto.randomBytes(16);

  // Generate Shared Secret
  const ecdh = crypto.createECDH(curve);
  ecdh.generateKeys();
  const shared_secret = ecdh.computeSecret(publicKey, 'base64', 'base64');

  // Derivate Secret
  // - Salt >= 16bytes
  // - Higher iterations
  // - Size = 2 * IV
  const d_shared_secret = crypto.pbkdf2Sync(shared_secret, s2, kdfIterations, 32, 'sha256');

  // Cipher Message
  const cipher = crypto.createCipheriv(cipherAlgo, d_shared_secret, iv);
  let encrypted_message = cipher.update(message, 'utf-8', 'base64');
  encrypted_message += cipher.final('base64');

  const hmac = crypto.createHmac(hmacAlgo, encrypted_message + s2.toString('base64'))
    .update(d_shared_secret)
    .digest();

  return [curve, encrypted_message, iv.toString('base64'), s2.toString('base64'), ecdh.getPublicKey('base64', 'compressed'), hmac.toString('base64')].join('|');
}

function ecies_decrypt(privateKey, payload) {
  const kdfIterations = 1000;
  const hmacAlgo = 'sha256';
//  const cipherAlgo = 'aes-256-cbc-hmac-sha256';
  const cipherAlgo = 'chacha20-poly1305';

  crypto = require('crypto');

  // TODO validate length
  var [curve, encrypted_message, ivBase64, s2Base64, publicKey, hmacBase64] = payload.split('|');

  const iv = Buffer.from(ivBase64, 'base64');

  // Generate Shared Secret
  const ecdh = crypto.createECDH(curve);
  ecdh.setPrivateKey(privateKey, 'base64', 'base64');
  const shared_secret = ecdh.computeSecret(publicKey, 'base64', 'base64');

  // Derivate Secret
  // - Salt >= 16bytes
  // - Higher iterations
  // - Size = 2 * IV
  const d_shared_secret = crypto.pbkdf2Sync(shared_secret, Buffer.from(s2Base64, 'base64'), kdfIterations, 32, 'sha256');

  const hmac = crypto.createHmac(hmacAlgo, encrypted_message + s2Base64)
    .update(d_shared_secret)
    .digest();

  if (!hmac.equals(Buffer.from(hmacBase64, 'base64'))) {
    throw new Error("Hmac are not equal");
  }
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

