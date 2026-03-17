/**
 * EJEMPLO: Integración de AthenAI como Middleware de Seguridad
 * 
 * Este ejemplo muestra cómo proteger tu backend Node.js/Express
 * usando AthenAI como capa de seguridad.
 * 
 * Arquitectura:
 * Cliente → Tu Backend (Express) → AthenAI API → Verificación → Continuar/Bloquear
 */

const express = require('express');
const axios = require('axios');

const app = express();
app.use(express.json());

// ============================================
// CONFIGURACIÓN DE ATHENAI
// ============================================

const ATHENAI_API = 'http://localhost:5000';
const ATHENAI_TOKEN = 'tu_jwt_token_aqui'; // Obtener desde /api/auth/login

// ============================================
// OPCIÓN 1: Verificar cada request con AthenAI
// ============================================

async function athenaiSecurityCheck(req, res, next) {
    try {
        // Crear firma del request para análisis
        const requestData = {
            ip: req.ip || req.connection.remoteAddress,
            method: req.method,
            path: req.path,
            headers: req.headers,
            body: req.body,
            timestamp: new Date().toISOString()
        };
        
        // Enviar a AthenAI para verificación
        const response = await axios.post(
            `${ATHENAI_API}/api/security/verify`,
            requestData,
            {
                headers: {
                    'Authorization': `Bearer ${ATHENAI_TOKEN}`,
                    'Content-Type': 'application/json'
                },
                timeout: 2000 // 2 segundos máximo
            }
        );
        
        if (response.data.safe) {
            // Request es seguro, continuar
            console.log(`✅ Request seguro desde ${requestData.ip}`);
            next();
        } else {
            // AthenAI detectó amenaza
            console.log(`🚨 Amenaza detectada: ${response.data.threat_type}`);
            
            res.status(403).json({
                error: 'Forbidden',
                message: 'Request bloqueado por sistema de seguridad',
                threat_id: response.data.threat_id
            });
        }
        
    } catch (error) {
        // Si AthenAI no responde, puedes decidir:
        // - Permitir el request (fail-open)
        // - Bloquearlo (fail-closed)
        
        console.error('⚠️ Error conectando con AthenAI:', error.message);
        
        // Fail-open: permitir en caso de error
        next();
    }
}

// ============================================
// OPCIÓN 2: Middleware simplificado (Rate Limit)
// ============================================

async function athenaiRateLimitCheck(req, res, next) {
    try {
        const ip = req.ip || req.connection.remoteAddress;
        
        // Consultar si la IP está dentro del límite
        const response = await axios.get(
            `${ATHENAI_API}/api/rate-limit/check/${ip}`,
            {
                headers: { 'Authorization': `Bearer ${ATHENAI_TOKEN}` }
            }
        );
        
        if (response.data.allowed) {
            next();
        } else {
            res.status(429).json({
                error: 'Too Many Requests',
                message: 'Rate limit excedido',
                retry_after: response.data.retry_after
            });
        }
        
    } catch (error) {
        console.error('Error verificando rate limit:', error.message);
        next(); // Fail-open
    }
}

// ============================================
// OPCIÓN 3: Verificar IP bloqueada solamente
// ============================================

async function athenaiIPCheck(req, res, next) {
    try {
        const ip = req.ip || req.connection.remoteAddress;
        
        const response = await axios.get(
            `${ATHENAI_API}/api/blocked-ips`,
            {
                headers: { 'Authorization': `Bearer ${ATHENAI_TOKEN}` }
            }
        );
        
        const blockedIPs = response.data.blocked_ips || [];
        
        if (blockedIPs.includes(ip)) {
            console.log(`🚫 IP bloqueada intentó acceder: ${ip}`);
            
            return res.status(403).json({
                error: 'Forbidden',
                message: 'IP bloqueada por seguridad'
            });
        }
        
        next();
        
    } catch (error) {
        console.error('Error verificando IP:', error.message);
        next();
    }
}

// ============================================
// APLICAR MIDDLEWARES
// ============================================

// Aplicar verificación de IP bloqueada a TODOS los endpoints
app.use(athenaiIPCheck);

// Aplicar rate limit a endpoints de API
app.use('/api/*', athenaiRateLimitCheck);

// Verificación completa solo en endpoints críticos
// app.use('/api/admin/*', athenaiSecurityCheck);

// ============================================
// TUS ENDPOINTS (PROTEGIDOS)
// ============================================

app.get('/api/users', (req, res) => {
    // Este endpoint está protegido por:
    // 1. IP Blocker
    // 2. Rate Limiter
    
    res.json({
        users: [
            { id: 1, name: 'Juan' },
            { id: 2, name: 'María' }
        ]
    });
});

app.post('/api/admin/delete-user', (req, res) => {
    // Este endpoint crítico tendría verificación completa
    // si descomentaras app.use('/api/admin/*', athenaiSecurityCheck);
    
    res.json({ success: true });
});

app.get('/api/public/info', (req, res) => {
    // Endpoint público, solo verifica IP bloqueada
    res.json({
        name: 'Mi API',
        version: '1.0.0'
    });
});

// ============================================
// ENVIAR LOGS A ATHENAI (Opcional)
// ============================================

async function logToAthenAI(req, res, next) {
    // Guardar el original res.json
    const originalJson = res.json.bind(res);
    
    // Capturar tiempo de inicio
    const startTime = Date.now();
    
    // Interceptar respuesta
    res.json = function(data) {
        const duration = Date.now() - startTime;
        
        // Enviar log a AthenAI de forma asíncrona (no bloquea respuesta)
        sendLogToAthenAI(req, res, duration, data).catch(err => {
            console.error('Error enviando log:', err.message);
        });
        
        // Enviar respuesta original
        return originalJson(data);
    };
    
    next();
}

async function sendLogToAthenAI(req, res, duration, responseData) {
    try {
        await axios.post(
            `${ATHENAI_API}/api/traffic/log`,
            {
                ip: req.ip,
                method: req.method,
                path: req.path,
                status_code: res.statusCode,
                response_time: duration,
                user_agent: req.headers['user-agent'],
                timestamp: new Date().toISOString()
            },
            {
                headers: { 'Authorization': `Bearer ${ATHENAI_TOKEN}` }
            }
        );
    } catch (error) {
        // Silenciar errores de logging
    }
}

// Aplicar logging a todo
app.use(logToAthenAI);

// ============================================
// HEALTH CHECK
// ============================================

app.get('/health', (req, res) => {
    res.json({
        status: 'OK',
        athenai_connected: true,
        timestamp: new Date().toISOString()
    });
});

// ============================================
// INICIAR SERVIDOR
// ============================================

const PORT = 8080;

app.listen(PORT, async () => {
    console.log(`🚀 Servidor ejecutándose en http://localhost:${PORT}`);
    console.log(`🛡️ Protegido por AthenAI en ${ATHENAI_API}`);
    
    // Verificar conexión con AthenAI
    try {
        const health = await axios.get(`${ATHENAI_API}/api/health`);
        console.log('✅ AthenAI conectado exitosamente');
        console.log(`   Versión: ${health.data.version || 'N/A'}`);
    } catch (error) {
        console.error('❌ No se pudo conectar con AthenAI');
        console.error('   Asegúrate de que AthenAI esté ejecutándose en puerto 5000');
    }
});

// ============================================
// MANEJO DE ERRORES
// ============================================

app.use((error, req, res, next) => {
    console.error('Error en servidor:', error);
    
    res.status(500).json({
        error: 'Internal Server Error',
        message: 'Ocurrió un error en el servidor'
    });
});

/**
 * INSTRUCCIONES DE USO:
 * 
 * 1. Instalar dependencias:
 *    npm install express axios
 * 
 * 2. Asegúrate de que AthenAI esté ejecutándose:
 *    cd athenai-dashboard
 *    .\venv_win\Scripts\python.exe api_backend.py
 * 
 * 3. Obtener JWT token de AthenAI:
 *    POST http://localhost:5000/api/auth/login
 *    Body: {"username": "admin", "password": "admin123"}
 *    → Copiar el token
 * 
 * 4. Pegar el token en la constante ATHENAI_TOKEN
 * 
 * 5. Ejecutar este servidor:
 *    node ejemplo_middleware_nodejs.js
 * 
 * 6. Probar:
 *    curl http://localhost:8080/api/users
 *    curl http://localhost:8080/health
 * 
 * PERSONALIZACIÓN:
 * 
 * - Comentar/descomentar middlewares según necesidad
 * - Ajustar fail-open vs fail-closed según criticidad
 * - Cambiar timeouts según latencia esperada
 * - Agregar más endpoints de verificación
 */
