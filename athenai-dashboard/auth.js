/**
 * Auth Service for AthenAI Frontend
 * 
 * Handles JWT authentication, token refresh, and API requests with auth
 */

const API_URL = 'http://localhost:5000';

class AuthService {
    constructor() {
        this.accessToken = localStorage.getItem('access_token');
        this.refreshToken = localStorage.getItem('refresh_token');
        this.user = JSON.parse(localStorage.getItem('user') || 'null');

        // Start token refresh timer
        this.startTokenRefreshTimer();
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
        try {
            // Call logout endpoint
            await fetch(`${API_URL}/api/auth/logout`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${this.accessToken}`
                }
            });
        } catch (error) {
            console.error('Logout error:', error);
        }

        // Clear local storage
        this.accessToken = null;
        this.refreshToken = null;
        this.user = null;

        localStorage.removeItem('access_token');
        localStorage.removeItem('refresh_token');
        localStorage.removeItem('user');

        // Stop refresh timer
        if (this.refreshTimer) {
            clearInterval(this.refreshTimer);
        }

        // Redirect to login
        window.location.href = 'login.html';
    }

    /**
     * Refresh access token
     */
    async refreshAccessToken() {
        if (!this.refreshToken) {
            this.logout();
            return false;
        }

        try {
            const response = await fetch(`${API_URL}/api/auth/refresh`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ refresh_token: this.refreshToken })
            });

            const data = await response.json();

            if (response.ok) {
                this.accessToken = data.access_token;
                localStorage.setItem('access_token', this.accessToken);
                return true;
            } else {
                // Refresh token expired, logout
                this.logout();
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
            this.logout();
            throw new Error('Not authenticated');
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

            // If 401, try to refresh token and retry
            if (response.status === 401) {
                const refreshed = await this.refreshAccessToken();

                if (refreshed) {
                    // Retry with new token
                    headers['Authorization'] = `Bearer ${this.accessToken}`;
                    return await fetch(url, {
                        ...options,
                        headers
                    });
                } else {
                    this.logout();
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
                this.logout();
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
