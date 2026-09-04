const express = require('express');
const QRCode = require('qrcode');
const { create } = require('@open-wa/wa-automate');

const app = express();
app.use(express.json());

const PORT = 3001;
let waClient = null;
let qrCodeData = null;
let status = 'DISCONNECTED'; // DISCONNECTED | QR_READY | CONNECTED

// ─── QR Code endpoint ───────────────────────────────────────────────────────
app.get('/qr', async (req, res) => {
    if (status === 'CONNECTED') {
        return res.json({ status: 'CONNECTED', message: 'Ya conectado — no necesitas escanear QR' });
    }
    if (!qrCodeData) {
        return res.json({ status: 'WAITING', message: 'Generando QR, espera unos segundos...' });
    }
    try {
        const qrImage = await QRCode.toDataURL(qrCodeData);
        res.json({ status: 'QR_READY', qr: qrImage });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// ─── Status endpoint ─────────────────────────────────────────────────────────
app.get('/status', (req, res) => {
    res.json({ status, connected: status === 'CONNECTED' });
});

// ─── Enviar mensaje ──────────────────────────────────────────────────────────
app.post('/send', async (req, res) => {
    if (status !== 'CONNECTED') {
        return res.status(503).json({ error: 'WhatsApp no conectado', status });
    }
    const { number, message } = req.body;
    if (!number || !message) {
        return res.status(400).json({ error: 'Se requiere number y message' });
    }
    try {
        // Formato: número internacional sin + (ej: 521234567890)
        const chatId = number.includes('@c.us') ? number : `${number}@c.us`;
        await waClient.sendText(chatId, message);
        console.log(`✅ Mensaje enviado a ${number}`);
        res.json({ success: true, to: number });
    } catch (e) {
        console.error(`❌ Error enviando mensaje: ${e.message}`);
        res.status(500).json({ error: e.message });
    }
});

// ─── Enviar alerta de seguridad formateada ───────────────────────────────────
app.post('/send-alert', async (req, res) => {
    if (status !== 'CONNECTED') {
        return res.status(503).json({ error: 'WhatsApp no conectado', status });
    }
    const { number, threat_type, ip, reason, timestamp } = req.body;
    if (!number || !threat_type) {
        return res.status(400).json({ error: 'Se requiere number y threat_type' });
    }
    const time = timestamp ? new Date(timestamp).toLocaleString('es-MX') : new Date().toLocaleString('es-MX');
    const message = [
        `🚨 *AthenAI — Alerta de Seguridad*`,
        ``,
        `⚠️ *Tipo:* ${threat_type}`,
        `🌐 *IP:* ${ip || 'Desconocida'}`,
        `📋 *Detalle:* ${reason || 'Ataque detectado y bloqueado'}`,
        `🕐 *Hora:* ${time}`,
        ``,
        `_Sistema WAF AthenAI — Protección activa_`
    ].join('\n');
    try {
        const chatId = number.includes('@c.us') ? number : `${number}@c.us`;
        await waClient.sendText(chatId, message);
        console.log(`✅ Alerta enviada a ${number}: ${threat_type}`);
        res.json({ success: true, to: number, threat_type });
    } catch (e) {
        console.error(`❌ Error enviando alerta: ${e.message}`);
        res.status(500).json({ error: e.message });
    }
});

// ─── Iniciar servidor HTTP primero ───────────────────────────────────────────
app.listen(PORT, () => {
    console.log(`🟢 AthenAI WhatsApp Service escuchando en puerto ${PORT}`);
    console.log(`📱 Abre http://localhost:${PORT}/qr en el dashboard para conectar`);
    startWhatsApp();
});

// ─── Iniciar open-wa ─────────────────────────────────────────────────────────
async function startWhatsApp() {
    try {
        const chromePath = process.env.PUPPETEER_EXECUTABLE_PATH || '/usr/bin/chromium';
        console.log(`🔍 Usando Chromium: ${chromePath}`);
        await create({
            sessionId: 'athenai',
            authTimeout: 90,
            blockCrashLogs: true,
            disableSpins: true,
            headless: true,
            logConsole: false,
            popup: false,
            qrTimeout: 0,
            useChrome: false,
            executablePath: chromePath,
            sessionDataPath: './session',
            waitForRefreshTimeout: 90,
            skipBrowserPasswordcheck: true,
            chromiumArgs: [
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-dev-shm-usage',
                '--disable-accelerated-2d-canvas',
                '--no-first-run',
                '--no-zygote',
                '--single-process',
                '--disable-gpu',
                '--window-size=1280,720',
            ],
        }, (client) => {
            waClient = client;
            status = 'CONNECTED';
            qrCodeData = null;
            console.log('✅ WhatsApp conectado exitosamente');
        }, {
            onQR: (qr) => {
                qrCodeData = qr;
                status = 'QR_READY';
                console.log('📱 QR listo — escanea en http://localhost:3001/qr');
            },
        });
    } catch (e) {
        console.error('❌ Error iniciando WhatsApp:', e.message);
        status = 'DISCONNECTED';
        // Reintentar en 30 segundos
        console.log('🔄 Reintentando en 30 segundos...');
        setTimeout(startWhatsApp, 30000);
    }
}
