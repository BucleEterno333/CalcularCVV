'use strict';

const express = require('express');
const forge   = require('node-forge');

const app = express();

// ============================================================
// CORS
// ============================================================
const ALLOWED_ORIGINS = [
    'https://astralchk.com',
    'https://www.astralchk.com',
    'http://localhost:3000',
    'http://127.0.0.1:5500',
    'http://localhost:5500'
];

app.use((req, res, next) => {
    const origin = req.headers.origin;
    if (origin && ALLOWED_ORIGINS.includes(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Vary', 'Origin');
    } else if (!origin) {
        res.setHeader('Access-Control-Allow-Origin', '*');
    } else {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Vary', 'Origin');
    }
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-API-Key, Authorization');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    if (req.method === 'OPTIONS') return res.status(204).end();
    next();
});

app.use(express.json({ limit: '256kb' }));

// ============================================================
// CONFIG
// ============================================================
const PORT         = process.env.PORT       || 3000;
const API_KEY      = process.env.CVV_API_KEY || null;
const DEFAULT_CVKA = process.env.CVK_A       || null;
const DEFAULT_CVKB = process.env.CVK_B       || null;

// ============================================================
// CRYPTO (DES CORREGIDO)
// ============================================================
function desEncryptBlock(keyHex, dataHex) {
    const cipher = forge.cipher.createCipher('DES-ECB', forge.util.hexToBytes(keyHex));
    cipher.start();
    cipher.update(forge.util.createBuffer(forge.util.hexToBytes(dataHex)));
    if (!cipher.finish()) throw new Error('DES encryption failed');
    return cipher.output.toHex().toUpperCase();
}

function hexXor(a, b) {
    const len = Math.max(a.length, b.length);
    a = a.padStart(len, '0');
    b = b.padStart(len, '0');
    const r = (BigInt('0x' + a) ^ BigInt('0x' + b)).toString(16).toUpperCase();
    return r.padStart(len, '0');
}

function decimalize(hexStr) {
    const map = { A:'0', B:'1', C:'2', D:'3', E:'4', F:'5' };
    const up = hexStr.toUpperCase();
    let out = '';
    for (const ch of up) if (ch >= '0' && ch <= '9') out += ch;
    for (const ch of up) if (map[ch] !== undefined) out += map[ch];
    return out;
}

function calculateCvv({ pan, expdate, serviceCode, cvka, cvkb }) {
    let panNorm = String(pan).replace(/\s+/g, '').replace(/\|/g, '');
    if (!/^\d{13,19}$/.test(panNorm)) throw new Error('PAN must be 13-19 digits');
    panNorm = panNorm.padStart(16, '0').slice(-16);

    const expClean = String(expdate).replace(/\//g, '').trim();
    if (!/^\d{4}$/.test(expClean)) throw new Error('expdate must be 4 digits (YYMM)');
    if (!/^\d{3}$/.test(String(serviceCode))) throw new Error('serviceCode must be 3 digits');

    const dataBlock = (expClean + serviceCode).padEnd(16, '0');
    const cvkaU = String(cvka).toUpperCase().trim();
    const cvkbU = String(cvkb).toUpperCase().trim();
    if (!/^[0-9A-F]{16}$/.test(cvkaU)) throw new Error('CVKA must be 16 hex chars');
    if (!/^[0-9A-F]{16}$/.test(cvkbU)) throw new Error('CVKB must be 16 hex chars');

    // ALGORITMO ESTÁNDAR (DES)
    const step1 = desEncryptBlock(cvkaU, panNorm);
    const step2 = hexXor(step1, dataBlock);
    const step3 = desEncryptBlock(cvkbU, step2); // <--- AQUÍ ESTABA EL ERROR (usaba 3DES)
    
    return decimalize(step3).slice(0, 3);
}

// ============================================================
// AUTH (opcional)
// ============================================================
function requireApiKey(req, res, next) {
    if (!API_KEY) return next();
    const provided = req.headers['x-api-key'] || req.query.api_key;
    if (provided !== API_KEY) {
        return res.status(401).json({ success: false, error: 'Unauthorized' });
    }
    next();
}

// ============================================================
// RUTAS
// ============================================================
app.get('/health',     (_q, r) => r.json({ status: 'OK', ts: Date.now() }));
app.get('/api/health', (_q, r) => r.json({ status: 'healthy' }));

app.post('/api/calculate-cvv', requireApiKey, (req, res) => {
    try {
        const b = req.body || {};
        const cvka = b.cvka || DEFAULT_CVKA;
        const cvkb = b.cvkb || DEFAULT_CVKB;

        if (!b.pan)          return res.status(400).json({ success: false, error: 'pan is required' });
        if (!b.expdate)      return res.status(400).json({ success: false, error: 'expdate (YYMM) is required' });
        if (!cvka || !cvkb)  return res.status(400).json({ success: false, error: 'cvka/cvkb required (body or env)' });

        const cvv = calculateCvv({
            pan: b.pan,
            expdate: b.expdate,
            serviceCode: b.service_code || b.serviceCode || '000',
            cvka, cvkb
        });
        res.json({ success: true, cvv });
    } catch (e) {
        res.status(400).json({ success: false, error: e.message });
    }
});

app.use((_q, r) => r.status(404).json({ error: 'Not found' }));

app.listen(PORT, '0.0.0.0', () => {
    console.log(`🔐 CVV Calculator API on port ${PORT}`);
    console.log(`   CVK_A: ${DEFAULT_CVKA ? 'loaded ✅' : 'MISSING ❌'}`);
    console.log(`   CVK_B: ${DEFAULT_CVKB ? 'loaded ✅' : 'MISSING ❌'}`);
});