// server.js
import express from 'express';
import multer from 'multer';
import fs from 'fs';
import crypto from 'crypto';


const app = express();

// Middleware per il parsing dei dati JSON e URL-encoded
app.use(express.json()); // Metodo che dice a app Express di usare il middleware per il parsing dei dati JSON. questo middleware è responsabile di analizzare i dati JSON inviati come corpo della richiesta e rendere i dati JSON disponibili come oggetto req.body. (req.body è un oggetto che contiene i dati inviati dal client al server)
app.use(express.urlencoded({ extended: true })); // se set su false, usa library querystring anziché qs, che non supporta nested objects. con questo middleware le app express accedono facilmente ai dati parsati dal corpo della richiesta POST. Il middleware analizza i dati URL-encoded e li rende disponibili come oggetto req.body.

// Serve i file statici dalla cartella 'client'
app.use(express.static('client'));

// Configurazione storage per multer
const upload = multer({ storage: multer.memoryStorage(),
    limits: { fileSize: 10 * 1024 * 1024 }, // Limite di 10MB per i file caricati, basta?
    fileFilter: (_req, file, cb) => {
        const fileAccettati =  ['application/pdf', 'application/octet-stream', 'text/plain'];
        if (fileAccettati.includes(file.mimetype)) {
            return cb(null, true);
        }
        cb(new Error('Tipo di file non accettato. Carica un file PDF, sig o pem.'));
    }
});

// Carica le chiavi RSA
const private_key = fs.readFileSync('./server/keys/private_key.pem', 'utf8');
const public_key = fs.readFileSync('./server/keys/public_key.pem', 'utf8');

// firma: RSA-PSS + SHA-256, firma dei byte del file (non dell'hash “precalcolato”)
app.post('/sign', upload.single('file'), (req, res) => {
    try {
        const data = req.file.buffer; // I dati del file caricato sono disponibili in req.file.buffer
        // Assicura che primi 5 byte corrispondano a "%PDF-"
        if (data.subarray(0, 5).toString('ascii') !== '%PDF-') { 
            throw new Error('Il file caricato non è un PDF valido.');
        }
        const sign = crypto.createSign('SHA256'); // Crea un oggetto di firma utilizzando l'algoritmo SHA-256
        sign.update(data); // Aggiunge i dati del file all'oggetto di firma
        sign.end(); // Segnala che non ci sono più dati da aggiungere
        const signature = sign.sign({
            key: private_key,
            padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
            saltLength: 32,
        });
        console.log('Ricevuto file:', req.file);
        
        res.json({
        fileName: req.file.originalname,
        signature: signature.toString('base64'),
        publicKeyPem: public_key,
        algorithm: 'RSA-PSS',
        hash: 'SHA-256',
        saltLength: 32,
    });
    } catch (error) {
    res.status(400).json({ error: error.message });
    }
});

// Verifica firma
app.post('/verify', upload.fields([
  { name: 'pdf', maxCount: 1 },
  { name: 'firma', maxCount: 1 },
  { name: 'chiave', maxCount: 1 }
]), (req, res) => {
    try {
        const pdfData = req.files['pdf'][0].buffer;
        const firmaData = req.files['firma'][0].buffer;
        const chiaveData = req.files['chiave'][0].buffer.toString('utf8');
        
        const verify = crypto.createVerify('SHA256');
        verify.update(pdfData);
        verify.end();

        const isValid = verify.verify({
            key: chiaveData,
            padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
            saltLength: 32,
        }, firmaData);

        res.json({ valid: isValid });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// Avvia il server
app.listen(3000, () => {
    console.log('Server in ascolto sulla porta 3000');
});