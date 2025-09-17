const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');

// Authentication configuration
const AUTH_CONFIG = {
    JWT_SECRET: process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production',
    JWT_EXPIRES_IN: '7d',
    BCRYPT_ROUNDS: 12,
    PASSWORD_RESET_EXPIRES: 3600000, // 1 hour
    EMAIL_VERIFICATION_EXPIRES: 86400000, // 24 hours
    MFA_WINDOW: 2, // TOTP window tolerance
    MAX_LOGIN_ATTEMPTS: 5,
    LOCKOUT_TIME: 900000, // 15 minutes
    SESSION_DURATION: 86400000 // 24 hours
};

// User roles
const USER_ROLES = {
    SUPER_ADMIN: 'super_admin',
    ORG_ADMIN: 'org_admin',
    VOTER: 'voter'
};

// Data storage paths
const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const SESSIONS_FILE = path.join(DATA_DIR, 'auth_sessions.json');
const RESET_TOKENS_FILE = path.join(DATA_DIR, 'reset_tokens.json');

class AuthenticationManager {
    constructor() {
        this.users = new Map();
        this.authSessions = new Map();
        this.resetTokens = new Map();
        this.loginAttempts = new Map();
        this.emailTransporter = null;
        
        this.init();
    }

    async init() {
        try {
            await this.loadData();
            await this.setupEmailTransporter();
            await this.createDefaultSuperAdmin();
            console.log('✅ Authentication Manager initialized');
        } catch (error) {
            console.error('Error initializing Auth Manager:', error);
        }
    }

    async setupEmailTransporter() {
        this.emailTransporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.EMAIL_USER || 'your-email@gmail.com',
                pass: process.env.EMAIL_PASS || 'your-app-password'
            }
        });
    }

    async loadData() {
        try {
            // Load users
            try {
                const usersData = await fs.readFile(USERS_FILE, 'utf8');
                const users = JSON.parse(usersData);
                this.users = new Map(Object.entries(users));
            } catch (error) {
                console.log('No existing users file, starting fresh');
            }

            // Load auth sessions
            try {
                const sessionsData = await fs.readFile(SESSIONS_FILE, 'utf8');
                const sessions = JSON.parse(sessionsData);
                this.authSessions = new Map(Object.entries(sessions));
            } catch (error) {
                console.log('No existing sessions file, starting fresh');
            }

            // Load reset tokens
            try {
                const tokensData = await fs.readFile(RESET_TOKENS_FILE, 'utf8');
                const tokens = JSON.parse(tokensData);
                this.resetTokens = new Map(Object.entries(tokens));
            } catch (error) {
                console.log('No existing reset tokens file, starting fresh');
            }
        } catch (error) {
            console.error('Error loading auth data:', error);
        }
    }

    async saveData() {
        try {
            // Save users
            const usersObj = Object.fromEntries(this.users);
            await fs.writeFile(USERS_FILE, JSON.stringify(usersObj, null, 2));

            // Save auth sessions
            const sessionsObj = Object.fromEntries(this.authSessions);
            await fs.writeFile(SESSIONS_FILE, JSON.stringify(sessionsObj, null, 2));

            // Save reset tokens
            const tokensObj = Object.fromEntries(this.resetTokens);
            await fs.writeFile(RESET_TOKENS_FILE, JSON.stringify(tokensObj, null, 2));
        } catch (error) {
            console.error('Error saving auth data:', error);
        }
    }

    async createDefaultSuperAdmin() {
        // Check if super admin exists
        const superAdminExists = Array.from(this.users.values())
            .some(user => user.role === USER_ROLES.SUPER_ADMIN);

        if (!superAdminExists) {
            const defaultAdmin = {
                id: 'super-admin-' + Date.now(),
                username: 'admin',
                email: 'admin@votesphere.com',
                password: await this.hashPassword('admin123'),
                role: USER_ROLES.SUPER_ADMIN,
                organizationId: null,
                isEmailVerified: true,
                mfaEnabled: false,
                mfaSecret: null,
                createdAt: new Date().toISOString(),
                lastLogin: null,
                loginAttempts: 0,
                lockedUntil: null
            };

            this.users.set(defaultAdmin.id, defaultAdmin);
            await this.saveData();
            
            console.log('✅ Default super admin created:');
            console.log('   Username: admin');
            console.log('   Password: admin123');
            console.log('   Email: admin@votesphere.com');
            console.log('   🔒 Please change these credentials immediately!');
        }
    }

    async hashPassword(password) {
        return await bcrypt.hash(password, AUTH_CONFIG.BCRYPT_ROUNDS);
    }

    async comparePassword(password, hash) {
        return await bcrypt.compare(password, hash);
    }

    generateJWT(user) {
        const payload = {
            userId: user.id,
            username: user.username,
            email: user.email,
            role: user.role,
            organizationId: user.organizationId
        };

        return jwt.sign(payload, AUTH_CONFIG.JWT_SECRET, {
            expiresIn: AUTH_CONFIG.JWT_EXPIRES_IN
        });
    }

    verifyJWT(token) {
        try {
            return jwt.verify(token, AUTH_CONFIG.JWT_SECRET);
        } catch (error) {
            return null;
        }
    }

    // User registration
    async registerUser(userData) {
        const { username, email, password, role, organizationId } = userData;

        // Validate input
        if (!username || !email || !password) {
            throw new Error('Username, email, and password are required');
        }

        // Check if user already exists
        const existingUser = Array.from(this.users.values())
            .find(user => user.username === username || user.email === email);

        if (existingUser) {
            throw new Error('User with this username or email already exists');
        }

        // Validate role
        if (!Object.values(USER_ROLES).includes(role)) {
            throw new Error('Invalid user role');
        }

        // Super admin can only be created by the system
        if (role === USER_ROLES.SUPER_ADMIN) {
            throw new Error('Super admin accounts cannot be created through registration');
        }

        // Hash password
        const hashedPassword = await this.hashPassword(password);

        // Create user
        const user = {
            id: crypto.randomUUID(),
            username,
            email,
            password: hashedPassword,
            role,
            organizationId: role === USER_ROLES.ORG_ADMIN ? organizationId : null,
            isEmailVerified: false,
            emailVerificationToken: crypto.randomBytes(32).toString('hex'),
            emailVerificationExpires: Date.now() + AUTH_CONFIG.EMAIL_VERIFICATION_EXPIRES,
            mfaEnabled: false,
            mfaSecret: null,
            createdAt: new Date().toISOString(),
            lastLogin: null,
            loginAttempts: 0,
            lockedUntil: null
        };

        this.users.set(user.id, user);
        await this.saveData();

        // Send verification email
        await this.sendVerificationEmail(user);

        return {
            id: user.id,
            username: user.username,
            email: user.email,
            role: user.role,
            organizationId: user.organizationId,
            isEmailVerified: user.isEmailVerified
        };
    }

    // User login
    async loginUser(credentials, ip) {
        const { username, password, mfaCode } = credentials;

        // Find user
        const user = Array.from(this.users.values())
            .find(u => u.username === username || u.email === username);

        if (!user) {
            throw new Error('Invalid credentials');
        }

        // Check if account is locked
        if (user.lockedUntil && user.lockedUntil > Date.now()) {
            throw new Error('Account is temporarily locked. Please try again later.');
        }

        // Check password
        const isPasswordValid = await this.comparePassword(password, user.password);
        if (!isPasswordValid) {
            await this.handleFailedLogin(user.id);
            throw new Error('Invalid credentials');
        }

        // Check MFA if enabled
        if (user.mfaEnabled) {
            if (!mfaCode) {
                throw new Error('MFA code required');
            }

            const isValidMFA = speakeasy.totp.verify({
                secret: user.mfaSecret,
                encoding: 'base32',
                token: mfaCode,
                window: AUTH_CONFIG.MFA_WINDOW
            });

            if (!isValidMFA) {
                await this.handleFailedLogin(user.id);
                throw new Error('Invalid MFA code');
            }
        }

        // Check email verification for voters
        if (user.role === USER_ROLES.VOTER && !user.isEmailVerified) {
            throw new Error('Please verify your email before logging in');
        }

        // Reset login attempts on successful login
        user.loginAttempts = 0;
        user.lockedUntil = null;
        user.lastLogin = new Date().toISOString();

        await this.saveData();

        // Generate JWT token
        const token = this.generateJWT(user);

        // Create session
        const sessionId = crypto.randomUUID();
        const session = {
            id: sessionId,
            userId: user.id,
            token,
            ip,
            createdAt: Date.now(),
            expiresAt: Date.now() + AUTH_CONFIG.SESSION_DURATION
        };

        this.authSessions.set(sessionId, session);
        await this.saveData();

        return {
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                role: user.role,
                organizationId: user.organizationId,
                mfaEnabled: user.mfaEnabled
            },
            token,
            sessionId
        };
    }

    async handleFailedLogin(userId) {
        const user = this.users.get(userId);
        if (!user) return;

        user.loginAttempts = (user.loginAttempts || 0) + 1;

        if (user.loginAttempts >= AUTH_CONFIG.MAX_LOGIN_ATTEMPTS) {
            user.lockedUntil = Date.now() + AUTH_CONFIG.LOCKOUT_TIME;
        }

        await this.saveData();
    }

    // Logout user
    async logoutUser(sessionId) {
        this.authSessions.delete(sessionId);
        await this.saveData();
    }

    // Verify session
    async verifySession(sessionId) {
        const session = this.authSessions.get(sessionId);
        
        if (!session || session.expiresAt < Date.now()) {
            if (session) {
                this.authSessions.delete(sessionId);
                await this.saveData();
            }
            return null;
        }

        const user = this.users.get(session.userId);
        if (!user) {
            this.authSessions.delete(sessionId);
            await this.saveData();
            return null;
        }

        return {
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                role: user.role,
                organizationId: user.organizationId
            },
            session
        };
    }

    // Email verification
    async verifyEmail(token) {
        const user = Array.from(this.users.values())
            .find(u => u.emailVerificationToken === token);

        if (!user) {
            throw new Error('Invalid verification token');
        }

        if (user.emailVerificationExpires < Date.now()) {
            throw new Error('Verification token has expired');
        }

        user.isEmailVerified = true;
        user.emailVerificationToken = null;
        user.emailVerificationExpires = null;

        await this.saveData();

        return true;
    }

    async sendVerificationEmail(user) {
        if (!this.emailTransporter) {
            console.log('Email transporter not configured, skipping verification email');
            return;
        }

        const verificationUrl = `${process.env.BASE_URL || 'http://localhost:3000'}/verify-email?token=${user.emailVerificationToken}`;

        const mailOptions = {
            from: process.env.EMAIL_USER || 'noreply@votesphere.com',
            to: user.email,
            subject: 'VoteSphere - Verify Your Email',
            html: `
                <h2>Welcome to VoteSphere!</h2>
                <p>Hello ${user.username},</p>
                <p>Please click the link below to verify your email address:</p>
                <a href="${verificationUrl}" style="background: #3b82f6; color: white; padding: 12px 24px; text-decoration: none; border-radius: 8px; display: inline-block;">Verify Email</a>
                <p>If you didn't create this account, please ignore this email.</p>
                <p>This link will expire in 24 hours.</p>
            `
        };

        try {
            await this.emailTransporter.sendMail(mailOptions);
            console.log(`✅ Verification email sent to ${user.email}`);
        } catch (error) {
            console.error('Error sending verification email:', error);
        }
    }

    // Password reset
    async requestPasswordReset(email) {
        const user = Array.from(this.users.values())
            .find(u => u.email === email);

        if (!user) {
            // Don't reveal if email exists or not
            return true;
        }

        const resetToken = crypto.randomBytes(32).toString('hex');
        const resetData = {
            userId: user.id,
            token: resetToken,
            expiresAt: Date.now() + AUTH_CONFIG.PASSWORD_RESET_EXPIRES
        };

        this.resetTokens.set(resetToken, resetData);
        await this.saveData();

        // Send reset email
        await this.sendPasswordResetEmail(user, resetToken);

        return true;
    }

    async sendPasswordResetEmail(user, resetToken) {
        if (!this.emailTransporter) {
            console.log('Email transporter not configured, skipping reset email');
            return;
        }

        const resetUrl = `${process.env.BASE_URL || 'http://localhost:3000'}/reset-password?token=${resetToken}`;

        const mailOptions = {
            from: process.env.EMAIL_USER || 'noreply@votesphere.com',
            to: user.email,
            subject: 'VoteSphere - Password Reset',
            html: `
                <h2>Password Reset Request</h2>
                <p>Hello ${user.username},</p>
                <p>You requested a password reset. Click the link below to reset your password:</p>
                <a href="${resetUrl}" style="background: #3b82f6; color: white; padding: 12px 24px; text-decoration: none; border-radius: 8px; display: inline-block;">Reset Password</a>
                <p>If you didn't request this reset, please ignore this email.</p>
                <p>This link will expire in 1 hour.</p>
            `
        };

        try {
            await this.emailTransporter.sendMail(mailOptions);
            console.log(`✅ Password reset email sent to ${user.email}`);
        } catch (error) {
            console.error('Error sending reset email:', error);
        }
    }

    async resetPassword(token, newPassword) {
        const resetData = this.resetTokens.get(token);

        if (!resetData || resetData.expiresAt < Date.now()) {
            throw new Error('Invalid or expired reset token');
        }

        const user = this.users.get(resetData.userId);
        if (!user) {
            throw new Error('User not found');
        }

        // Hash new password
        user.password = await this.hashPassword(newPassword);
        user.loginAttempts = 0;
        user.lockedUntil = null;

        // Remove reset token
        this.resetTokens.delete(token);

        await this.saveData();

        return true;
    }

    // MFA Setup
    async setupMFA(userId) {
        const user = this.users.get(userId);
        if (!user) {
            throw new Error('User not found');
        }

        // Generate MFA secret
        const secret = speakeasy.generateSecret({
            name: `VoteSphere (${user.username})`,
            issuer: 'VoteSphere',
            length: 32
        });

        // Generate QR code
        const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);

        // Store secret temporarily (will be confirmed when user verifies)
        user.mfaTempSecret = secret.base32;

        await this.saveData();

        return {
            secret: secret.base32,
            qrCode: qrCodeUrl,
            manualEntryKey: secret.base32
        };
    }

    async enableMFA(userId, verificationCode) {
        const user = this.users.get(userId);
        if (!user || !user.mfaTempSecret) {
            throw new Error('MFA setup not initiated');
        }

        // Verify the code
        const isValid = speakeasy.totp.verify({
            secret: user.mfaTempSecret,
            encoding: 'base32',
            token: verificationCode,
            window: AUTH_CONFIG.MFA_WINDOW
        });

        if (!isValid) {
            throw new Error('Invalid verification code');
        }

        // Enable MFA
        user.mfaEnabled = true;
        user.mfaSecret = user.mfaTempSecret;
        user.mfaTempSecret = null;

        await this.saveData();

        return true;
    }

    async disableMFA(userId, verificationCode) {
        const user = this.users.get(userId);
        if (!user || !user.mfaEnabled) {
            throw new Error('MFA not enabled');
        }

        // Verify the code
        const isValid = speakeasy.totp.verify({
            secret: user.mfaSecret,
            encoding: 'base32',
            token: verificationCode,
            window: AUTH_CONFIG.MFA_WINDOW
        });

        if (!isValid) {
            throw new Error('Invalid verification code');
        }

        // Disable MFA
        user.mfaEnabled = false;
        user.mfaSecret = null;

        await this.saveData();

        return true;
    }

    // User management
    async getUserById(userId) {
        const user = this.users.get(userId);
        if (!user) return null;

        return {
            id: user.id,
            username: user.username,
            email: user.email,
            role: user.role,
            organizationId: user.organizationId,
            isEmailVerified: user.isEmailVerified,
            mfaEnabled: user.mfaEnabled,
            createdAt: user.createdAt,
            lastLogin: user.lastLogin
        };
    }

    async getUsersByOrganization(organizationId) {
        return Array.from(this.users.values())
            .filter(user => user.organizationId === organizationId)
            .map(user => ({
                id: user.id,
                username: user.username,
                email: user.email,
                role: user.role,
                isEmailVerified: user.isEmailVerified,
                createdAt: user.createdAt,
                lastLogin: user.lastLogin
            }));
    }

    async updateUser(userId, updates) {
        const user = this.users.get(userId);
        if (!user) {
            throw new Error('User not found');
        }

        // Only allow certain fields to be updated
        const allowedUpdates = ['email', 'username'];
        const filteredUpdates = {};

        for (const key of allowedUpdates) {
            if (updates[key] !== undefined) {
                filteredUpdates[key] = updates[key];
            }
        }

        // Check for email/username conflicts
        if (filteredUpdates.email || filteredUpdates.username) {
            const conflictUser = Array.from(this.users.values())
                .find(u => u.id !== userId && (
                    (filteredUpdates.email && u.email === filteredUpdates.email) ||
                    (filteredUpdates.username && u.username === filteredUpdates.username)
                ));

            if (conflictUser) {
                throw new Error('Username or email already exists');
            }
        }

        // If email is being updated, require re-verification
        if (filteredUpdates.email && filteredUpdates.email !== user.email) {
            filteredUpdates.isEmailVerified = false;
            filteredUpdates.emailVerificationToken = crypto.randomBytes(32).toString('hex');
            filteredUpdates.emailVerificationExpires = Date.now() + AUTH_CONFIG.EMAIL_VERIFICATION_EXPIRES;
        }

        Object.assign(user, filteredUpdates);
        await this.saveData();

        // Send verification email if email was updated
        if (filteredUpdates.email) {
            await this.sendVerificationEmail(user);
        }

        return this.getUserById(userId);
    }

    async deleteUser(userId) {
        const user = this.users.get(userId);
        if (!user) {
            throw new Error('User not found');
        }

        // Cannot delete super admin
        if (user.role === USER_ROLES.SUPER_ADMIN) {
            throw new Error('Cannot delete super admin');
        }

        this.users.delete(userId);

        // Remove associated sessions
        for (const [sessionId, session] of this.authSessions.entries()) {
            if (session.userId === userId) {
                this.authSessions.delete(sessionId);
            }
        }

        await this.saveData();

        return true;
    }

    // Role checking utilities
    hasRole(user, role) {
        return user.role === role;
    }

    isSuperAdmin(user) {
        return this.hasRole(user, USER_ROLES.SUPER_ADMIN);
    }

    isOrgAdmin(user) {
        return this.hasRole(user, USER_ROLES.ORG_ADMIN);
    }

    isVoter(user) {
        return this.hasRole(user, USER_ROLES.VOTER);
    }

    canAccessOrganization(user, organizationId) {
        if (this.isSuperAdmin(user)) return true;
        if (this.isOrgAdmin(user)) return user.organizationId === organizationId;
        return false;
    }
}

module.exports = {
    AuthenticationManager,
    USER_ROLES,
    AUTH_CONFIG
};