'use strict';

const express = require('express');
const forge   = require('node-forge');

const app = express();
app.use(express.json({ limit: '256kb' }));

const PORT         = process.env.PORT       || 3000;
const API_KEY      = process.env.CVV_API_KEY || null;
const DEFAULT_CVKA = process.env.CVK_A       || null;
const DEFAULT_CVKB = process.env.CVK_B       || null;

/* ============================================================
 *  CRYPTO
 * ============================================================ */
function desEncryptBlock(keyHex, dataHex) {
    const cipher = forge.cipher.createCipher('DES-ECB', forge.util.hexToBytes(keyHex));
    cipher.start();
    cipher.update(forge.util.createBuffer(forge.util.hexToBytes(dataHex)));
    if (!cipher.finish()) throw new Error('DES encryption failed');
    return cipher.output.toHex().toUpperCase();
}

function tripleDesEncryptBlock(keyHex, dataHex) {
    let key = keyHex.toUpperCase();
    if (key.length === 32) key = key + key.slice(0, 16);   // 2-key → 3-key
    if (key.length !== 48) throw new Error('3DES key must be 16 or 24 bytes');
    const cipher = forge.cipher.createCipher('3DES-ECB', forge.util.hexToBytes(key));
    cipher.start();
    cipher.update(forge.util.createBuffer(forge.util.hexToBytes(dataHex)));
    if (!cipher.finish()) throw new Error('3DES encryption failed');
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

    const step1 = desEncryptBlock(cvkaU, panNorm);
    const step2 = hexXor(step1, dataBlock);
    const step3 = tripleDesEncryptBlock(cvkaU + cvkbU, step2);
    return decimalize(step3).slice(0, 3);
}

/* ============================================================
 *  PARSER  →  PAN|MM|YYYY|CVV  (y variantes)
 * ============================================================ */
function parseCardLine(line) {
    const raw = String(line || '').trim();
    if (!raw || raw.startsWith('#')) return null;
    const parts = raw.split('|').map(s => s.trim());
    if (parts.length < 2) return null;

    const pan = parts[0].replace(/\D/g, '');
    if (!/^\d{13,19}$/.test(pan)) return null;

    let expdate = null;       // formato interno: YYMM
    let originalCvv = null;

    if (parts.length >= 4) {
        // PAN|MM|YYYY|CVV   o   PAN|MM|YY|CVV
        const mm = parts[1].padStart(2, '0');
        const yy = parts[2].length === 4 ? parts[2].slice(-2) : parts[2].padStart(2, '0');
        expdate = yy + mm;
        originalCvv = parts[3].replace(/\D/g, '') || null;
    } else if (parts.length === 3) {
        const p1 = parts[1], p2 = parts[2];
        if (p1.length === 4 && /^\d{4}$/.test(p1)) {
            // PAN|YYMM|CVV
            expdate = p1;
            originalCvv = p2.replace(/\D/g, '') || null;
        } else if (p1.length <= 2 && (p2.length === 2 || p2.length === 4)) {
            // PAN|MM|YYYY   o   PAN|MM|YY
            const mm = p1.padStart(2, '0');
            const yy = p2.length === 4 ? p2.slice(-2) : p2.padStart(2, '0');
            expdate = yy + mm;
        } else {
            return null;
        }
    } else if (parts.length === 2) {
        // PAN|YYMM
        if (!/^\d{4}$/.test(parts[1])) return null;
        expdate = parts[1];
    } else {
        return null;
    }

    return { pan, expdate, originalCvv, raw };
}

/* ============================================================
 *  FORMATTER  →  PAN|MM|YYYY|CVV
 * ============================================================ */
function formatCard(pan, expdateYYMM, cvv) {
    const yy = expdateYYMM.slice(0, 2);
    const mm = expdateYYMM.slice(2, 4);
    const yyyy = '20' + yy;
    return `${pan}|${mm}|${yyyy}|${cvv}`;
}

/* ============================================================
 *  AUTH
 * ============================================================ */
function requireApiKey(req, res, next) {
    if (!API_KEY) return next();
    const provided = req.headers['x-api-key'] || req.query.api_key;
    if (provided !== API_KEY) return res.status(401).json({ success: false, error: 'Unauthorized' });
    next();
}

/* ============================================================
 *  RUTAS
 * ============================================================ */
app.get('/health',        (_q, r) => r.json({ status: 'OK', ts: Date.now() }));
app.get('/api/health',    (_q, r) => r.json({ status: 'healthy' }));

app.post('/api/calculate-cvv', requireApiKey, (req, res) => {
    try {
        const b = req.body || {};
        const cvv = calculateCvv({
            pan: b.pan,
            expdate: b.expdate,
            serviceCode: b.service_code || b.serviceCode || '101',
            cvka: b.cvka || DEFAULT_CVKA,
            cvkb: b.cvkb || DEFAULT_CVKB
        });
        res.json({ success: true, cvv });
    } catch (e) {
        res.status(400).json({ success: false, error: e.message });
    }
});

/* -------- BATCH -------- */
app.post('/api/calculate-cvv/batch', requireApiKey, (req, res) => {
    try {
        const b = req.body || {};
        const cvka = b.cvka || DEFAULT_CVKA;
        const cvkb = b.cvkb || DEFAULT_CVKB;
        const serviceCode = b.service_code || b.serviceCode || '000';   // CVV2 por defecto
        const includeDetails = b.details !== false;

        if (!cvka || !cvkb)
            return res.status(400).json({ success: false, error: 'cvka/cvkb required (body or CVK_A/CVK_B env)' });

        // Acepta: {cards: [...]}, {text: "..."}, {cards: "..."}
        let lines = [];
        if (Array.isArray(b.cards))        lines = b.cards.map(String);
        else if (typeof b.text === 'string') lines = b.text.split(/\r?\n/);
        else if (typeof b.cards === 'string') lines = b.cards.split(/\r?\n/);
        else return res.status(400).json({ success: false, error: 'Provide "text" (string) or "cards" (array)' });

        const results   = [];
        const outputArr = [];
        let ok = 0, fail = 0;

        for (const raw of lines) {
            const parsed = parseCardLine(raw);
            if (!parsed) {
                if (raw.trim() && !raw.trim().startsWith('#')) {
                    results.push({ input: raw, success: false, error: 'Invalid format' });
                    fail++;
                }
                continue;
            }
            try {
                const cvv = calculateCvv({ ...parsed, serviceCode, cvka, cvkb });
                const outLine = formatCard(parsed.pan, parsed.expdate, cvv);

                results.push({
                    success: true,
                    input: parsed.raw,
                    pan: parsed.pan,
                    expdate: parsed.expdate,
                    service_code: serviceCode,
                    original_cvv: parsed.originalCvv,
                    calculated_cvv: cvv,
                    match: parsed.originalCvv ? parsed.originalCvv === cvv : null
                });
                outputArr.push(outLine);
                ok++;
            } catch (e) {
                results.push({ input: parsed.raw, success: false, error: e.message });
                fail++;
            }
        }

        res.json({
            success: true,
            service_code: serviceCode,
            total: results.length,
            ok,
            fail,
            output_text: outputArr.join('\n'),
            output_lines: outputArr,
            ...(includeDetails ? { results } : {})
        });
    } catch (err) {
        res.status(400).json({ success: false, error: err.message });
    }
});

app.use((_q, r) => r.status(404).json({ error: 'Not found' }));

app.listen(PORT, '0.0.0.0', () => {
    console.log(`🔐 CVV API on :${PORT}`);
    console.log(`   POST /api/calculate-cvv          (single)`);
    console.log(`   POST /api/calculate-cvv/batch    (batch)`);
    console.log(`   Auth: ${API_KEY ? 'X-API-Key required' : 'DISABLED'}`);
});