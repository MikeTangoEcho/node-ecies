<template>
  <div>
    <h1>ECIES Encryption</h1>
    <h2 v-if="hasCrypto()">Crypto Enabled</h2>
    <h2 v-else>Crypto Disabled, must access the app through https</h2>
    <table align="center">
        <tr>
            <td>Algo Name</td>
            <td>
                {{ algo_name }}
            </td>
        </tr>
        <tr>
            <td>Named Curve</td>
            <td>
                <select v-model="algo_named_curve">
                  <option>P-256</option>
                  <option>P-384</option>
                  <option>P-521</option>
                </select>
            </td>
        </tr>
        <tr>
            <td>Cipher Name</td>
            <td>
                <select v-model="cipher_name">
                  <option disabled>AES-CBC</option>
                  <option disabled>AES-CTR</option>
                  <option>AES-GCM</option>
                  <option disabled>RSA-OAEP</option>
                </select>
            </td>
        </tr>
        <tr>
            <td>Cipher Length</td>
            <td>
                <select v-model="cipher_length">
                  <option>128</option>
                  <option>256</option>
                  <option>512</option>
                </select>
            </td>
        </tr>
        <tr><td colspan="2">
            <button v-on:click="onGenerateKey">Generate Key</button>
        </td></tr>
        <tr>
            <td><textarea rows="15" cols="55" v-model="private_key" placeholder="Private Key" /></td>
            <td><textarea rows="15" cols="55" v-model="public_key" placeholder="Public Key" /></td>
        </tr>
        <tr>
            <td><button v-on:click="onEncrypt">Encrypt</button></td>
            <td><button v-on:click="onDecrypt">Decrypt</button></td>
        </tr>
        <tr>
            <td><textarea rows="15" cols="55" v-model="message" placeholder="Message" /></td>
            <td><textarea rows="15" cols="55" v-model="encrypted_message" placeholder="Encrypted Message" /></td>
        </tr>
    </table>
  </div>
</template>

<script>
export default {
  rules: {
    'no-console': 'off',
  },
  name: 'KeyGen',
  data() {
    return {
        private_key : null,
        public_key: null,
        message: null,
        encrypted_message: null,
        algo_name: "ECDH",
        algo_named_curve: "P-256",
        cipher_name: "AES-GCM",
        cipher_length: 128,
    }
  },
  methods: {
    hasCrypto: function () {
        return (window.crypto.subtle !==  undefined);
    },
    onGenerateKey: async function () {
        var key = await window.crypto.subtle.generateKey(
            {
                name: this.algo_name,
                namedCurve: this.algo_named_curve,
            },
            true,
            ["deriveKey", "deriveBits"]
        );
        var privateKey = await window.crypto.subtle.exportKey("jwk", key.privateKey);
        var publicKey = await window.crypto.subtle.exportKey("jwk", key.publicKey);
        this.private_key = JSON.stringify(privateKey, null, 2);
        this.public_key = JSON.stringify(publicKey, null, 2);
    },
    onEncrypt: async function () {
        var publicKey = await window.crypto.subtle.importKey(
            "jwk",
            JSON.parse(this.public_key),
            {
                name: this.algo_name,
                namedCurve: this.algo_named_curve,
            },
            false,
            []
        );

        var temporaryKey = await window.crypto.subtle.generateKey(
            {
                name: this.algo_name,
                namedCurve: this.algo_named_curve,
            },
            true,
            ["deriveKey", "deriveBits"]
        );

        // Shared Key
        /*
        var sharedKey = await window.crypto.subtle.deriveKey(
            {
                name: this.algo_name,
                namedCurve: this.algo_named_curve,
                public: publicKey,
            },
            temporaryKey.privateKey,
            {
                name: this.cipher_name,
                length: this.cipher_length
            },
            true,
            ["encrypt"]
        );
        */

        // HKDF
        var sharedKey = await window.crypto.subtle.deriveBits(
            {
                name: this.algo_name,
                namedCurve: this.algo_named_curve,
                public: publicKey,
            },
            temporaryKey.privateKey,
            256
        );
        var hkdfKey =  await window.crypto.subtle.importKey(
            "raw",
            sharedKey,
            {
                name: "HKDF"
            },
            false,
            ["deriveKey", "deriveBits"]
        );
        var kdfSharedKey = await window.crypto.subtle.deriveKey(
            {
                name: "HKDF",
                salt: new Uint8Array(),
                info: new TextEncoder().encode('test'),
                hash: 'SHA-256'
            },
            hkdfKey,
            {
                name: this.cipher_name,
                length: this.cipher_length
            },
            true,
            ["encrypt"]
        );

        // Crypt
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        var encryptedMessage = await window.crypto.subtle.encrypt(
            {
                name: this.cipher_name,
                length: this.cipher_length,
                iv: iv
            },
            kdfSharedKey,
            new TextEncoder().encode(this.message)
        );

        var payload = {
            "iv": Buffer.from(iv).toString('base64'),
            "public_key": await window.crypto.subtle.exportKey("jwk", temporaryKey.publicKey),
            "encrypted_message": Buffer.from(encryptedMessage).toString('base64')
        };
        this.encrypted_message = JSON.stringify(payload, null, 2);
        console.debug(this.message + " -> " + this.encrypted_message);
    },
    onDecrypt: async function () {
        var payload = JSON.parse(this.encrypted_message);

        var privateKey = await window.crypto.subtle.importKey(
            "jwk",
            JSON.parse(this.private_key),
            {
                name: this.algo_name,
                namedCurve: this.algo_named_curve,
            },
            false,
            ["deriveKey", "deriveBits"]
        );

        var publicKey = await window.crypto.subtle.importKey(
            "jwk",
            payload.public_key,
            {
                name: this.algo_name,
                namedCurve: this.algo_named_curve,
            },
            false,
            []
        );

        // Shared Key
        /*
        var sharedKey = await window.crypto.subtle.deriveKey(
            {
                name: this.algo_name,
                namedCurve: this.algo_named_curve,
                public: publicKey,
            },
            privateKey,
            {
                name: this.cipher_name,
                length: this.cipher_length
            },
            false,
            ["decrypt"]
        );
        */

        // HKDF
        var sharedKey = await window.crypto.subtle.deriveBits(
            {
                name: this.algo_name,
                namedCurve: this.algo_named_curve,
                public: publicKey,
            },
            privateKey,
            256
        );
        var hkdfKey =  await window.crypto.subtle.importKey(
            "raw",
            sharedKey,
            {
                name: "HKDF"
            },
            false,
            ["deriveKey", "deriveBits"]
        );
        var kdfSharedKey = await window.crypto.subtle.deriveKey(
            {
                name: "HKDF",
                salt: new Uint8Array(),
                info: new TextEncoder().encode('test'),
                hash: 'SHA-256'
            },
            hkdfKey,
            {
                name: this.cipher_name,
                length: this.cipher_length
            },
            true,
            ["decrypt"]
        );

        var message = await window.crypto.subtle.decrypt(
            {
                name: this.cipher_name,
                length: this.cipher_length,
                iv: Buffer.from(payload.iv, 'base64')
            },
            kdfSharedKey,
            Buffer.from(payload.encrypted_message, 'base64')
        );

        this.message = Buffer.from(message).toString('utf-8');
        console.debug(payload.encrypted_message + " -> " + this.message);
    }
  }
}
</script>

