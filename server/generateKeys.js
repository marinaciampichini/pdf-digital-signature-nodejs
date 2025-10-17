import fs from 'fs';
import crypto from 'crypto';

const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding : {
        type: 'spki',
        format: 'pem',
    },
    privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem',
    }
});

fs.writeFileSync('./keys/private_key.pem', privateKey);
fs.writeFileSync('./keys/public_key.pem', publicKey);
console.log('Chiavi generate e salvate in ./keys/');