/**
 * Auth Service for AthenAI Frontend
 * 
 * Handles JWT authentication, token refresh, and API requests with auth
 */

const API_URL = window.location.origin;

class AuthService {
    constructor() {
        this.accessToken = localStorage.getItem('access_token');
        this.refreshToken = localStorage.getItem('refresh_token');
        this.user = JSON.parse(localStorage.getItem('user') || 'null');
        this._isRedirecting = false; // guard contra redirects múltiples simultáneos

        // Verificar si el access token ya expiró al cargar desde localStorage
        if (this.accessToken && this._isTokenExpired(this.accessToken)) {
            this.accessToken = null;
        }
        // También verificar refresh token
        if (this.refreshToken && this._isTokenExpired(this.refreshToken)) {
            this.refreshToken = null;
            localStorage.removeItem('refresh_token');
        }

        // Solo iniciar el timer si el token es válido
        if (this.accessToken) {
            this.startTokenRefreshTimer();
        }
    }

    /**
     * Decode JWT and check if it is expired
     */
    _isTokenExpired(token) {
        try {
            const payload = JSON.parse(atob(token.split('.')[1]));
            return payload.exp && (payload.exp * 1000) < Date.now();
        } catch (e) {
            return true; // Si no se puede decodificar, tratar como expirado
        }
    }

    /**
     * Check if user is authenticated
     */
    isAuthenticated() {
        return !!this.accessToken;
    }

    /**
     * Get current user
     */
    getUser() {
        return this.user;
    }

    /**
     * Get access token
     */
    getAccessToken() {
        return this.accessToken;
    }

    /**
     * Login
     */
    async login(username, password) {
        try {
            const response = await fetch(`${API_URL}/api/auth/login`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username, password })
            });

            const data = await response.json();

            if (response.ok) {
                this.accessToken = data.access_token;
                this.refreshToken = data.refresh_token;
                this.user = data.user;

                localStorage.setItem('access_token', this.accessToken);
                localStorage.setItem('refresh_token', this.refreshToken);
                localStorage.setItem('user', JSON.stringify(this.user));

                this.startTokenRefreshTimer();

                return { success: true, user: this.user };
            } else {
                return { success: false, error: data.error };
            }
        } catch (error) {
            console.error('Login error:', error);
            return { success: false, error: 'Connection error' };
        }
    }

    /**
     * Logout
     */
    async logout() {
        if (this._isRedirecting) return; // evitar doble logout
        this._isRedirecting = true;

        // Detener todos los timers PRIMERO para cortar el polling
        if (this.refreshTimer) {
            clearInterval(this.refreshTimer);
            this.refreshTimer = null;
        }

        // Intentar llamar al backend solo si hay token válido (best-effort)
        if (this.accessToken) {
            try {
                await fetch(`${API_URL}/api/auth/logout`, {
                    method: 'POST',
                    headers: { 'Authorization': `Bearer ${this.accessToken}` }
                });
            } catch (error) {
                // Ignorar errores — el objetivo es limpiar localmente
            }
        }

        // Limpiar estado y localStorage
        this.accessToken = null;
        this.refreshToken = null;
        this.user = null;
        localStorage.removeItem('access_token');
        localStorage.removeItem('refresh_token');
        localStorage.removeItem('user');

        window.location.href = 'login.html';
    }

    /**
     * Logout silencioso sin llamar al backend (para casos de token inválido)
     */
    _forceRedirectToLogin() {
        if (this._isRedirecting) return;
        this._isRedirecting = true;
        if (this.refreshTimer) { clearInterval(this.refreshTimer); this.refreshTimer = null; }
        this.accessToken = null;
        this.refreshToken = null;
        this.user = null;
        localStorage.removeItem('access_token');
        localStorage.removeItem('refresh_token');
        localStorage.removeItem('user');
        window.location.href = 'login.html';
    }

    /**
     * Refresh access token
     */
    async refreshAccessToken() {
        if (!this.refreshToken) {
            this._forceRedirectToLogin();
            return false;
        }

        try {
            const response = await fetch(`${API_URL}/api/auth/refresh`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ refresh_token: this.refreshToken })
            });

            const data = await response.json();

            if (response.ok) {
                this.accessToken = data.access_token;
                localStorage.setItem('access_token', this.accessToken);
                return true;
            } else {
                // Refresh token expirado o inválido — redirigir sin llamar al backend
                this._forceRedirectToLogin();
                return false;
            }
        } catch (error) {
            console.error('Token refresh error:', error);
            return false;
        }
    }

    /**
     * Start automatic token refresh timer
     * Refresh token every 50 minutes (tokens expire in 1 hour)
     */
    startTokenRefreshTimer() {
        if (this.refreshTimer) {
            clearInterval(this.refreshTimer);
        }

        // Refresh every 50 minutes
        this.refreshTimer = setInterval(() => {
            this.refreshAccessToken();
        }, 50 * 60 * 1000);
    }

    /**
     * Make authenticated API request
     */
    async fetch(url, options = {}) {
        if (!this.accessToken) {
            // FIX 4: Intentar refresh antes de redirigir, en lugar de logout inmediato
            if (this.refreshToken) {
                const refreshed = await this.refreshAccessToken();
                if (!refreshed) {
                    window.location.href = 'login.html';
                    throw new Error('Not authenticated');
                }
            } else {
                window.location.href = 'login.html';
                throw new Error('Not authenticated');
            }
        }

        // Add authorization header
        const headers = {
            ...options.headers,
            'Authorization': `Bearer ${this.accessToken}`
        };

        try {
            const response = await fetch(url, {
                ...options,
                headers
            });

            // Si 401, intentar refresh UNA sola vez
            if (response.status === 401) {
                const refreshed = await this.refreshAccessToken();
                if (refreshed) {
                    headers['Authorization'] = `Bearer ${this.accessToken}`;
                    const retryResponse = await fetch(url, { ...options, headers });
                    // Si el retry también da 401, el token nuevo es inválido → redirigir
                    if (retryResponse.status === 401) {
                        this._forceRedirectToLogin();
                        throw new Error('Authentication failed after refresh');
                    }
                    return retryResponse;
                } else {
                    // refreshAccessToken ya manejó la redirección
                    throw new Error('Authentication failed');
                }
            }

            return response;
        } catch (error) {
            console.error('Fetch error:', error);
            throw error;
        }
    }

    /**
     * Verify current token
     */
    async verifyToken() {
        if (!this.accessToken) {
            return false;
        }

        try {
            const response = await fetch(`${API_URL}/api/auth/me`, {
                headers: {
                    'Authorization': `Bearer ${this.accessToken}`
                }
            });

            if (response.ok) {
                const data = await response.json();
                this.user = data.user;
                localStorage.setItem('user', JSON.stringify(this.user));
                return true;
            } else {
                // Token inválido — redirigir sin llamar al backend de nuevo
                this._forceRedirectToLogin();
                return false;
            }
        } catch (error) {
            console.error('Token verification error:', error);
            return false;
        }
    }
}

// Create global auth service instance and expose it to window
const authService = new AuthService();
window.authService = authService;

// Check authentication on page load
if (window.location.pathname !== '/login.html' && !window.location.pathname.endsWith('/login.html')) {
    if (!authService.isAuthenticated()) {
        window.location.href = 'login.html';
    } else {
        // Verify token is still valid
        authService.verifyToken().then(valid => {
            if (!valid) {
                window.location.href = 'login.html';
            }
        });
    }
}
