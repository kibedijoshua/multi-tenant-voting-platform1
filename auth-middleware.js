// Authentication middleware for VoteSphere
const { USER_ROLES } = require('./auth');

class AuthMiddleware {
    constructor(authManager) {
        this.authManager = authManager;
    }

    // Extract session from request
    extractSession(req) {
        // Try session cookie first
        const sessionId = req.session?.sessionId || 
                         req.cookies?.sessionId || 
                         req.headers['x-session-id'];

        // Try JWT token as fallback
        const authHeader = req.headers.authorization;
        const token = authHeader && authHeader.startsWith('Bearer ') 
            ? authHeader.substring(7) 
            : null;

        return { sessionId, token };
    }

    // Authenticate user middleware
    authenticate() {
        return async (req, res, next) => {
            try {
                const { sessionId, token } = this.extractSession(req);

                // Try session authentication first
                if (sessionId) {
                    const sessionData = await this.authManager.verifySession(sessionId);
                    if (sessionData) {
                        req.user = sessionData.user;
                        req.session.data = sessionData.session;
                        return next();
                    }
                }

                // Try JWT token authentication
                if (token) {
                    const decoded = this.authManager.verifyJWT(token);
                    if (decoded) {
                        const user = await this.authManager.getUserById(decoded.userId);
                        if (user) {
                            req.user = user;
                            return next();
                        }
                    }
                }

                // No valid authentication found
                return res.status(401).json({
                    error: 'Authentication required',
                    code: 'AUTH_REQUIRED'
                });

            } catch (error) {
                console.error('Authentication error:', error);
                return res.status(500).json({
                    error: 'Authentication system error',
                    code: 'AUTH_ERROR'
                });
            }
        };
    }

    // Optional authentication (doesn't fail if not authenticated)
    optionalAuthenticate() {
        return async (req, res, next) => {
            try {
                const { sessionId, token } = this.extractSession(req);

                // Try session authentication first
                if (sessionId) {
                    const sessionData = await this.authManager.verifySession(sessionId);
                    if (sessionData) {
                        req.user = sessionData.user;
                        req.session.data = sessionData.session;
                        return next();
                    }
                }

                // Try JWT token authentication
                if (token) {
                    const decoded = this.authManager.verifyJWT(token);
                    if (decoded) {
                        const user = await this.authManager.getUserById(decoded.userId);
                        if (user) {
                            req.user = user;
                            return next();
                        }
                    }
                }

                // Continue without authentication
                req.user = null;
                next();

            } catch (error) {
                console.error('Optional authentication error:', error);
                req.user = null;
                next();
            }
        };
    }

    // Require specific role
    requireRole(role) {
        return async (req, res, next) => {
            if (!req.user) {
                return res.status(401).json({
                    error: 'Authentication required',
                    code: 'AUTH_REQUIRED'
                });
            }

            if (req.user.role !== role) {
                return res.status(403).json({
                    error: 'Insufficient permissions',
                    code: 'INSUFFICIENT_PERMISSIONS',
                    required: role,
                    current: req.user.role
                });
            }

            next();
        };
    }

    // Require any of the specified roles
    requireAnyRole(roles) {
        return async (req, res, next) => {
            if (!req.user) {
                return res.status(401).json({
                    error: 'Authentication required',
                    code: 'AUTH_REQUIRED'
                });
            }

            if (!roles.includes(req.user.role)) {
                return res.status(403).json({
                    error: 'Insufficient permissions',
                    code: 'INSUFFICIENT_PERMISSIONS',
                    required: roles,
                    current: req.user.role
                });
            }

            next();
        };
    }

    // Super admin only
    requireSuperAdmin() {
        return this.requireRole(USER_ROLES.SUPER_ADMIN);
    }

    // Organization admin or super admin
    requireOrgAdmin() {
        return this.requireAnyRole([USER_ROLES.SUPER_ADMIN, USER_ROLES.ORG_ADMIN]);
    }

    // Any admin role
    requireAdmin() {
        return this.requireAnyRole([USER_ROLES.SUPER_ADMIN, USER_ROLES.ORG_ADMIN]);
    }

    // Require access to specific organization
    requireOrganizationAccess(getOrganizationId) {
        return async (req, res, next) => {
            if (!req.user) {
                return res.status(401).json({
                    error: 'Authentication required',
                    code: 'AUTH_REQUIRED'
                });
            }

            const organizationId = typeof getOrganizationId === 'function' 
                ? getOrganizationId(req) 
                : req.params.organizationId || req.body.organizationId;

            if (!organizationId) {
                return res.status(400).json({
                    error: 'Organization ID required',
                    code: 'ORG_ID_REQUIRED'
                });
            }

            // Super admin has access to all organizations
            if (req.user.role === USER_ROLES.SUPER_ADMIN) {
                return next();
            }

            // Organization admin can only access their own organization
            if (req.user.role === USER_ROLES.ORG_ADMIN) {
                if (req.user.organizationId === organizationId) {
                    return next();
                } else {
                    return res.status(403).json({
                        error: 'Access denied to this organization',
                        code: 'ORG_ACCESS_DENIED'
                    });
                }
            }

            // Voters don't have organization-level access
            return res.status(403).json({
                error: 'Insufficient permissions for organization access',
                code: 'INSUFFICIENT_PERMISSIONS'
            });
        };
    }

    // Require email verification
    requireEmailVerification() {
        return async (req, res, next) => {
            if (!req.user) {
                return res.status(401).json({
                    error: 'Authentication required',
                    code: 'AUTH_REQUIRED'
                });
            }

            // Skip verification check for super admin
            if (req.user.role === USER_ROLES.SUPER_ADMIN) {
                return next();
            }

            if (!req.user.isEmailVerified) {
                return res.status(403).json({
                    error: 'Email verification required',
                    code: 'EMAIL_VERIFICATION_REQUIRED'
                });
            }

            next();
        };
    }

    // Rate limiting middleware
    rateLimit(requests = 10, windowMs = 60000) {
        const attempts = new Map();

        return (req, res, next) => {
            const key = req.ip || req.connection.remoteAddress;
            const now = Date.now();
            
            // Get current attempts for this IP
            const ipAttempts = attempts.get(key) || [];
            
            // Remove old attempts outside the window
            const recentAttempts = ipAttempts.filter(time => now - time < windowMs);
            
            if (recentAttempts.length >= requests) {
                return res.status(429).json({
                    error: 'Too many requests',
                    code: 'RATE_LIMIT_EXCEEDED',
                    retryAfter: Math.ceil(windowMs / 1000)
                });
            }

            // Add current attempt
            recentAttempts.push(now);
            attempts.set(key, recentAttempts);

            next();
        };
    }

    // Login rate limiting (stricter)
    loginRateLimit() {
        return this.rateLimit(5, 300000); // 5 attempts per 5 minutes
    }

    // API rate limiting
    apiRateLimit() {
        return this.rateLimit(100, 60000); // 100 requests per minute
    }

    // Validation middleware
    validateInput(schema) {
        return (req, res, next) => {
            const { error } = schema.validate(req.body);
            if (error) {
                return res.status(400).json({
                    error: 'Validation error',
                    code: 'VALIDATION_ERROR',
                    details: error.details.map(d => d.message)
                });
            }
            next();
        };
    }

    // CSRF protection middleware
    csrfProtection() {
        return (req, res, next) => {
            // Skip CSRF for GET requests
            if (req.method === 'GET') {
                return next();
            }

            const token = req.headers['x-csrf-token'] || 
                         req.body._csrf || 
                         req.query._csrf;

            const sessionToken = req.session?.csrfToken;

            if (!token || !sessionToken || token !== sessionToken) {
                return res.status(403).json({
                    error: 'Invalid CSRF token',
                    code: 'CSRF_ERROR'
                });
            }

            next();
        };
    }

    // Security headers middleware
    securityHeaders() {
        return (req, res, next) => {
            // Prevent clickjacking
            res.setHeader('X-Frame-Options', 'DENY');
            
            // Prevent MIME type sniffing
            res.setHeader('X-Content-Type-Options', 'nosniff');
            
            // Enable XSS protection
            res.setHeader('X-XSS-Protection', '1; mode=block');
            
            // Referrer policy
            res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
            
            // Content Security Policy
            res.setHeader('Content-Security-Policy', 
                "default-src 'self'; " +
                "script-src 'self' 'unsafe-inline'; " +
                "style-src 'self' 'unsafe-inline'; " +
                "img-src 'self' data: blob:; " +
                "font-src 'self'; " +
                "connect-src 'self'; " +
                "frame-ancestors 'none';"
            );

            next();
        };
    }

    // Session management helper
    createSession(req, sessionId) {
        if (req.session) {
            req.session.sessionId = sessionId;
            req.session.csrfToken = require('crypto').randomBytes(32).toString('hex');
        }
    }

    // Logout helper
    async logout(req, res) {
        const { sessionId } = this.extractSession(req);
        
        if (sessionId) {
            await this.authManager.logoutUser(sessionId);
        }

        if (req.session) {
            req.session.destroy();
        }

        res.clearCookie('sessionId');
        
        return res.json({ 
            success: true, 
            message: 'Logged out successfully' 
        });
    }
}

module.exports = AuthMiddleware;