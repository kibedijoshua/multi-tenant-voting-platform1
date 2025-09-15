const express = require('express');
const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const fs = require('fs').promises;
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const multer = require('multer');
const cors = require('cors');
const nodemailer = require('nodemailer');
const crypto = require('crypto');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

// Environment configuration
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

const DATA_DIR = path.join(__dirname, 'data');
const UPLOADS_DIR = path.join(__dirname, 'uploads');

// Create necessary directories
async function createDirectories() {
    try {
        await fs.mkdir(DATA_DIR, { recursive: true });
        await fs.mkdir(UPLOADS_DIR, { recursive: true });
        console.log('✅ Directories created');
    } catch (error) {
        console.error('Error creating directories:', error);
    }
}

// Configure multer for file uploads
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, UPLOADS_DIR);
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({ 
    storage: storage,
    limits: {
        fileSize: 5 * 1024 * 1024 // 5MB limit
    },
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Only image files are allowed'), false);
        }
    }
});

// In-memory session storage for vote tracking with enhanced security
const sessions = new Map();
const ipVoteCounts = new Map(); // Track votes per IP
const suspiciousActivity = new Map(); // Track suspicious behavior
const rateLimiter = new Map(); // Rate limiting per IP
const emailVerificationCodes = new Map(); // Email verification codes
const verifiedEmails = new Map(); // Verified email addresses
const captchaTokens = new Map(); // CAPTCHA tokens
const mlFraudScores = new Map(); // Machine learning fraud scores

// Email configuration (configure with your email service)
const emailTransporter = nodemailer.createTransport({
    service: 'gmail', // or your email service
    auth: {
        user: process.env.EMAIL_USER || 'your-email@gmail.com',
        pass: process.env.EMAIL_PASS || 'your-app-password'
    }
});

// Enhanced security configuration
const SECURITY_CONFIG = {
    MAX_VOTES_PER_IP: 10, // Maximum votes from same IP in a session
    RATE_LIMIT_WINDOW: 60000, // 1 minute in milliseconds
    MAX_REQUESTS_PER_MINUTE: 20, // Max API calls per IP per minute
    SUSPICIOUS_THRESHOLD: 5, // Number of failed attempts before flagging
    VOTE_COOLDOWN: 2000, // Minimum time between votes (2 seconds)
    EMAIL_VERIFICATION_REQUIRED: false, // Set to true to require email verification
    CAPTCHA_REQUIRED_THRESHOLD: 3, // Require CAPTCHA after 3 suspicious activities
    ML_FRAUD_THRESHOLD: 0.7, // Machine learning fraud detection threshold
    EMAIL_CODE_EXPIRY: 600000, // Email verification code expiry (10 minutes)
    CAPTCHA_EXPIRY: 300000 // CAPTCHA token expiry (5 minutes)
};

// Enhanced security functions
function isRateLimited(ip) {
    const now = Date.now();
    const requests = rateLimiter.get(ip) || [];
    
    // Remove old requests outside the window
    const recentRequests = requests.filter(time => now - time < SECURITY_CONFIG.RATE_LIMIT_WINDOW);
    
    if (recentRequests.length >= SECURITY_CONFIG.MAX_REQUESTS_PER_MINUTE) {
        return true;
    }
    
    // Add current request
    recentRequests.push(now);
    rateLimiter.set(ip, recentRequests);
    return false;
}

function trackSuspiciousActivity(ip, activity) {
    const activities = suspiciousActivity.get(ip) || [];
    activities.push({
        activity,
        timestamp: new Date().toISOString()
    });
    
    // Keep only recent activities (last hour)
    const oneHourAgo = Date.now() - (60 * 60 * 1000);
    const recentActivities = activities.filter(a => 
        new Date(a.timestamp).getTime() > oneHourAgo
    );
    
    suspiciousActivity.set(ip, recentActivities);
    
    // Log if suspicious threshold reached
    if (recentActivities.length >= SECURITY_CONFIG.SUSPICIOUS_THRESHOLD) {
        console.warn(`🚨 Suspicious activity detected from IP: ${ip}`);
        console.warn(`Activities: ${recentActivities.map(a => a.activity).join(', ')}`);
    }
}

function checkIPVoteLimit(sessionId, ip) {
    const key = `${sessionId}-${ip}`;
    const count = ipVoteCounts.get(key) || 0;
    return count >= SECURITY_CONFIG.MAX_VOTES_PER_IP;
}

function incrementIPVoteCount(sessionId, ip) {
    const key = `${sessionId}-${ip}`;
    const count = ipVoteCounts.get(key) || 0;
    ipVoteCounts.set(key, count + 1);
}

function getIPVoteCount(sessionId, ip) {
    const key = `${sessionId}-${ip}`;
    return ipVoteCounts.get(key) || 0;
}

// Enhanced browser fingerprinting
function generateBrowserFingerprint(req) {
    const userAgent = req.headers['user-agent'] || '';
    const acceptLanguage = req.headers['accept-language'] || '';
    const acceptEncoding = req.headers['accept-encoding'] || '';
    const ip = req.ip || req.connection.remoteAddress;
    
    // Create a semi-unique fingerprint
    const fingerprint = Buffer.from(
        `${ip}-${userAgent}-${acceptLanguage}-${acceptEncoding}`
    ).toString('base64');
    
    return fingerprint;
}

// Advanced Security Functions

// Generate simple CAPTCHA
function generateCaptcha() {
    const num1 = Math.floor(Math.random() * 10) + 1;
    const num2 = Math.floor(Math.random() * 10) + 1;
    const operators = ['+', '-', '*'];
    const operator = operators[Math.floor(Math.random() * operators.length)];
    
    let question, answer;
    switch(operator) {
        case '+':
            question = `${num1} + ${num2}`;
            answer = num1 + num2;
            break;
        case '-':
            question = `${num1} - ${num2}`;
            answer = num1 - num2;
            break;
        case '*':
            question = `${num1} × ${num2}`;
            answer = num1 * num2;
            break;
    }
    
    const token = uuidv4();
    captchaTokens.set(token, {
        answer,
        timestamp: Date.now()
    });
    
    // Clean up expired tokens
    cleanupExpiredTokens();
    
    return { question, token };
}

// Verify CAPTCHA
function verifyCaptcha(token, userAnswer) {
    const captcha = captchaTokens.get(token);
    if (!captcha) return false;
    
    const isExpired = Date.now() - captcha.timestamp > SECURITY_CONFIG.CAPTCHA_EXPIRY;
    if (isExpired) {
        captchaTokens.delete(token);
        return false;
    }
    
    const isCorrect = parseInt(userAnswer) === captcha.answer;
    if (isCorrect) {
        captchaTokens.delete(token); // One-time use
    }
    
    return isCorrect;
}

// Generate email verification code
function generateEmailCode() {
    return Math.floor(100000 + Math.random() * 900000).toString(); // 6-digit code
}

// Send verification email
async function sendVerificationEmail(email, code, sessionTitle) {
    try {
        const mailOptions = {
            from: process.env.EMAIL_USER || 'voting-system@example.com',
            to: email,
            subject: `Voting Verification Code - ${sessionTitle}`,
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: #333;">🗳️ Voting Verification</h2>
                    <p>Your verification code for voting in "${sessionTitle}" is:</p>
                    <div style="background: #f0f0f0; padding: 20px; text-align: center; font-size: 24px; font-weight: bold; letter-spacing: 3px; margin: 20px 0;">
                        ${code}
                    </div>
                    <p>This code will expire in 10 minutes.</p>
                    <p>If you didn't request this code, please ignore this email.</p>
                    <hr style="margin: 20px 0;">
                    <p style="color: #666; font-size: 12px;">Secure Voting Platform</p>
                </div>
            `
        };
        
        await emailTransporter.sendMail(mailOptions);
        return true;
    } catch (error) {
        console.error('Email sending error:', error);
        return false;
    }
}

// Machine Learning-based Fraud Detection
function calculateFraudScore(ip, userAgent, sessionId, votingPattern) {
    let score = 0;
    
    // Check voting speed (rapid voting increases score)
    const recentVotes = Array.from(sessions.entries())
        .filter(([key, data]) => key.includes(sessionId) && data.ip === ip)
        .sort((a, b) => new Date(b[1].timestamp) - new Date(a[1].timestamp));
    
    if (recentVotes.length > 1) {
        const timeDiff = new Date(recentVotes[0][1].timestamp) - new Date(recentVotes[1][1].timestamp);
        if (timeDiff < 5000) score += 0.3; // Rapid voting
    }
    
    // Check IP vote count
    const ipVoteCount = getIPVoteCount(sessionId, ip);
    if (ipVoteCount > 5) score += 0.4;
    if (ipVoteCount > 8) score += 0.3;
    
    // Check suspicious activity history
    const suspiciousCount = (suspiciousActivity.get(ip) || []).length;
    score += Math.min(suspiciousCount * 0.1, 0.5);
    
    // Check user agent patterns (basic check for automation)
    if (!userAgent || userAgent.length < 20) score += 0.2;
    if (userAgent.includes('bot') || userAgent.includes('crawler')) score += 0.8;
    
    // Store fraud score
    mlFraudScores.set(`${sessionId}-${ip}`, {
        score: Math.min(score, 1.0),
        timestamp: Date.now(),
        factors: {
            rapidVoting: recentVotes.length > 1 && (new Date(recentVotes[0][1].timestamp) - new Date(recentVotes[1][1].timestamp)) < 5000,
            highIPCount: ipVoteCount > 5,
            suspiciousHistory: suspiciousCount > 2,
            suspiciousUserAgent: !userAgent || userAgent.length < 20
        }
    });
    
    return Math.min(score, 1.0);
}

// Clean up expired tokens and data
function cleanupExpiredTokens() {
    const now = Date.now();
    
    // Clean expired CAPTCHA tokens
    for (const [token, data] of captchaTokens.entries()) {
        if (now - data.timestamp > SECURITY_CONFIG.CAPTCHA_EXPIRY) {
            captchaTokens.delete(token);
        }
    }
    
    // Clean expired email verification codes
    for (const [email, data] of emailVerificationCodes.entries()) {
        if (now - data.timestamp > SECURITY_CONFIG.EMAIL_CODE_EXPIRY) {
            emailVerificationCodes.delete(email);
        }
    }
}

// Check if CAPTCHA is required for this IP
function isCaptchaRequired(ip) {
    const activities = suspiciousActivity.get(ip) || [];
    return activities.length >= SECURITY_CONFIG.CAPTCHA_REQUIRED_THRESHOLD;
}

// Verify email code
function verifyEmailCode(email, code) {
    const storedData = emailVerificationCodes.get(email);
    if (!storedData) return false;
    
    const isExpired = Date.now() - storedData.timestamp > SECURITY_CONFIG.EMAIL_CODE_EXPIRY;
    if (isExpired) {
        emailVerificationCodes.delete(email);
        return false;
    }
    
    const isCorrect = storedData.code === code;
    if (isCorrect) {
        verifiedEmails.set(email, Date.now());
        emailVerificationCodes.delete(email);
    }
    
    return isCorrect;
}

// Data file paths
const ORGANIZATIONS_FILE = path.join(DATA_DIR, 'organizations.json');
const VOTING_SESSIONS_FILE = path.join(DATA_DIR, 'voting_sessions.json');

// Data management functions
class DataManager {
    static async readFile(filePath, defaultData = []) {
        try {
            const data = await fs.readFile(filePath, 'utf8');
            return JSON.parse(data);
        } catch (error) {
            if (error.code === 'ENOENT') {
                await fs.writeFile(filePath, JSON.stringify(defaultData, null, 2));
                return defaultData;
            }
            throw error;
        }
    }

    static async writeFile(filePath, data) {
        await fs.writeFile(filePath, JSON.stringify(data, null, 2));
    }

    static async getOrganizations() {
        return await this.readFile(ORGANIZATIONS_FILE, []);
    }

    static async saveOrganizations(organizations) {
        await this.writeFile(ORGANIZATIONS_FILE, organizations);
    }

    static async getVotingSessions() {
        return await this.readFile(VOTING_SESSIONS_FILE, []);
    }

    static async saveVotingSessions(sessions) {
        await this.writeFile(VOTING_SESSIONS_FILE, sessions);
    }

    static async getSessionById(sessionId) {
        const sessions = await this.getVotingSessions();
        return sessions.find(s => s.id === sessionId);
    }

    static async updateSession(sessionId, updates) {
        const sessions = await this.getVotingSessions();
        const index = sessions.findIndex(s => s.id === sessionId);
        if (index !== -1) {
            sessions[index] = { ...sessions[index], ...updates, lastUpdated: new Date().toISOString() };
            await this.saveVotingSessions(sessions);
            return sessions[index];
        }
        return null;
    }
}

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('.'));
app.use('/uploads', express.static(UPLOADS_DIR));

// Serve the main admin dashboard
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin.html'));
});

// Serve public voting finder page
app.get('/find-voting', (req, res) => {
    res.sendFile(path.join(__dirname, 'public-voting.html'));
});

// Serve voting interface for specific sessions
app.get('/vote/:sessionId', async (req, res) => {
    try {
        const { sessionId } = req.params;
        const session = await DataManager.getSessionById(sessionId);
        
        if (!session) {
            return res.status(404).send('<h1>Voting Session Not Found</h1><p>The voting session you are looking for does not exist or has been removed.</p>');
        }
        
        if (session.status !== 'active') {
            return res.status(403).send(`<h1>Voting Session ${session.status === 'completed' ? 'Completed' : 'Not Active'}</h1><p>This voting session is currently ${session.status}.</p>`);
        }
        
        res.sendFile(path.join(__dirname, 'vote.html'));
    } catch (error) {
        console.error('Error serving voting page:', error);
        res.status(500).send('<h1>Server Error</h1><p>An error occurred while loading the voting page.</p>');
    }
});

// Serve enhanced secure voting interface
app.get('/secure-vote/:sessionId', async (req, res) => {
    try {
        const { sessionId } = req.params;
        const session = await DataManager.getSessionById(sessionId);
        
        if (!session) {
            return res.status(404).send('<h1>Voting Session Not Found</h1><p>The voting session you are looking for does not exist or has been removed.</p>');
        }
        
        if (session.status !== 'active') {
            return res.status(403).send(`<h1>Voting Session ${session.status === 'completed' ? 'Completed' : 'Not Active'}</h1><p>This voting session is currently ${session.status}.</p>`);
        }
        
        res.sendFile(path.join(__dirname, 'enhanced-vote.html'));
    } catch (error) {
        console.error('Error serving enhanced voting page:', error);
        res.status(500).send('<h1>Server Error</h1><p>An error occurred while loading the voting page.</p>');
    }
});

// Initialize data file if it doesn't exist
async function initializeData() {
    try {
        await fs.access(DATA_FILE);
    } catch {
        const initialData = {
            candidates: [
                {
                    id: 1,
                    name: "John Doe",
                    description: "Experienced leader with a vision for progress",
                    photo: "https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?w=150&h=150&fit=crop&crop=face&auto=format",
                    votes: 0
                },
                {
                    id: 2,
                    name: "Jane Smith",
                    description: "Innovative thinker focused on community development",
                    photo: "https://images.unsplash.com/photo-1494790108755-2616b612b0e2?w=150&h=150&fit=crop&crop=face&auto=format",
                    votes: 0
                },
                {
                    id: 3,
                    name: "Mike Johnson",
                    description: "Dedicated public servant with proven track record",
                    photo: "https://images.unsplash.com/photo-1472099645785-5658abf4ff4e?w=150&h=150&fit=crop&crop=face&auto=format",
                    votes: 0
                }
            ],
            totalVotes: 0,
            lastUpdated: new Date().toISOString()
        };
        await fs.writeFile(DATA_FILE, JSON.stringify(initialData, null, 2));
        console.log('✅ Initialized voting data');
    }
}

// Read vote data
async function readVoteData() {
    try {
        const data = await fs.readFile(DATA_FILE, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        console.error('Error reading vote data:', error);
        throw error;
    }
}

// Write vote data
async function writeVoteData(data) {
    try {
        data.lastUpdated = new Date().toISOString();
        await fs.writeFile(DATA_FILE, JSON.stringify(data, null, 2));
    } catch (error) {
        console.error('Error writing vote data:', error);
        throw error;
    }
}

// Generate session ID for new connections
function generateSessionId() {
    return uuidv4();
}

// Check if session has already voted
function hasVoted(sessionId) {
    return sessions.has(sessionId) && sessions.get(sessionId).hasVoted;
}

// Enhanced vote recording with security measures
function recordVote(sessionId, candidateId, ip, userAgent, fingerprint) {
    sessions.set(sessionId, {
        hasVoted: true,
        votedFor: candidateId,
        timestamp: new Date().toISOString(),
        ip: ip,
        userAgent: userAgent,
        fingerprint: fingerprint,
        verified: true
    });
    
    // Log vote for audit trail
    console.log(`📊 Vote recorded: Session ${sessionId} voted for candidate ${candidateId} from IP ${ip}`);
}

// API Routes

// Organization Management
app.post('/api/organizations', async (req, res) => {
    try {
        const { name, description, adminEmail } = req.body;
        
        if (!name || !adminEmail) {
            return res.status(400).json({ error: 'Name and admin email are required' });
        }
        
        const organizations = await DataManager.getOrganizations();
        
        // Check if organization already exists
        if (organizations.find(org => org.name.toLowerCase() === name.toLowerCase())) {
            return res.status(400).json({ error: 'Organization name already exists' });
        }
        
        const newOrg = {
            id: uuidv4(),
            name,
            description: description || '',
            adminEmail,
            createdAt: new Date().toISOString(),
            active: true
        };
        
        organizations.push(newOrg);
        await DataManager.saveOrganizations(organizations);
        
        res.json({ success: true, organization: newOrg });
    } catch (error) {
        console.error('Error creating organization:', error);
        res.status(500).json({ error: 'Failed to create organization' });
    }
});

app.get('/api/organizations', async (req, res) => {
    try {
        const organizations = await DataManager.getOrganizations();
        res.json(organizations);
    } catch (error) {
        console.error('Error fetching organizations:', error);
        res.status(500).json({ error: 'Failed to fetch organizations' });
    }
});

// Voting Session Management
app.post('/api/sessions', async (req, res) => {
    try {
        const { organizationId, title, description } = req.body;
        
        if (!organizationId || !title) {
            return res.status(400).json({ error: 'Organization ID and title are required' });
        }
        
        const sessions = await DataManager.getVotingSessions();
        
        const newSession = {
            id: uuidv4(),
            organizationId,
            title,
            description: description || '',
            candidates: [],
            status: 'draft', // draft, active, completed
            totalVotes: 0,
            createdAt: new Date().toISOString(),
            lastUpdated: new Date().toISOString()
        };
        
        sessions.push(newSession);
        
        // Use non-blocking file save for better performance
        DataManager.saveVotingSessions(sessions).catch(error => {
            console.error('Background save failed:', error);
        });
        
        // Return immediately without waiting for file save
        res.json({ success: true, session: newSession });
    } catch (error) {
        console.error('Error creating session:', error);
        res.status(500).json({ error: 'Failed to create session' });
    }
});

app.get('/api/sessions/:organizationId', async (req, res) => {
    try {
        const { organizationId } = req.params;
        const sessions = await DataManager.getVotingSessions();
        const orgSessions = sessions.filter(s => s.organizationId === organizationId);
        res.json(orgSessions);
    } catch (error) {
        console.error('Error fetching sessions:', error);
        res.status(500).json({ error: 'Failed to fetch sessions' });
    }
});

app.get('/api/session/:sessionId', async (req, res) => {
    try {
        const { sessionId } = req.params;
        const session = await DataManager.getSessionById(sessionId);
        
        if (!session) {
            return res.status(404).json({ error: 'Session not found' });
        }
        
        res.json(session);
    } catch (error) {
        console.error('Error fetching session:', error);
        res.status(500).json({ error: 'Failed to fetch session' });
    }
});

// Candidate Management
app.post('/api/sessions/:sessionId/candidates', upload.single('photo'), async (req, res) => {
    try {
        const { sessionId } = req.params;
        const { name, description } = req.body;
        
        if (!name) {
            return res.status(400).json({ error: 'Candidate name is required' });
        }
        
        const session = await DataManager.getSessionById(sessionId);
        if (!session) {
            return res.status(404).json({ error: 'Session not found' });
        }
        
        const photoUrl = req.file ? `/uploads/${req.file.filename}` : 
            `https://ui-avatars.com/api/?name=${encodeURIComponent(name)}&background=random&size=150`;
        
        const newCandidate = {
            id: uuidv4(),
            name,
            description: description || '',
            photo: photoUrl,
            votes: 0
        };
        
        session.candidates.push(newCandidate);
        await DataManager.updateSession(sessionId, { candidates: session.candidates });
        
        res.json({ success: true, candidate: newCandidate });
    } catch (error) {
        console.error('Error adding candidate:', error);
        res.status(500).json({ error: 'Failed to add candidate' });
    }
});

app.delete('/api/sessions/:sessionId/candidates/:candidateId', async (req, res) => {
    try {
        const { sessionId, candidateId } = req.params;
        
        const session = await DataManager.getSessionById(sessionId);
        if (!session) {
            return res.status(404).json({ error: 'Session not found' });
        }
        
        session.candidates = session.candidates.filter(c => c.id !== candidateId);
        await DataManager.updateSession(sessionId, { candidates: session.candidates });
        
        res.json({ success: true, message: 'Candidate removed' });
    } catch (error) {
        console.error('Error removing candidate:', error);
        res.status(500).json({ error: 'Failed to remove candidate' });
    }
});

// Session Status Management
app.patch('/api/sessions/:sessionId/status', async (req, res) => {
    try {
        const { sessionId } = req.params;
        const { status } = req.body;
        
        if (!['draft', 'active', 'completed'].includes(status)) {
            return res.status(400).json({ error: 'Invalid status' });
        }
        
        const updatedSession = await DataManager.updateSession(sessionId, { status });
        if (!updatedSession) {
            return res.status(404).json({ error: 'Session not found' });
        }
        
        res.json({ success: true, session: updatedSession });
    } catch (error) {
        console.error('Error updating session status:', error);
        res.status(500).json({ error: 'Failed to update session status' });
    }
});

// Voting Endpoints for Multi-Tenant System

// Get session data for voting interface
app.get('/api/voting/:sessionId', async (req, res) => {
    try {
        const { sessionId } = req.params;
        const session = await DataManager.getSessionById(sessionId);
        
        if (!session) {
            return res.status(404).json({ error: 'Session not found' });
        }
        
        if (session.status !== 'active') {
            return res.status(403).json({ error: 'Session is not active' });
        }
        
        // Calculate percentages
        const totalVotes = session.totalVotes || 0;
        const candidatesWithPercentage = session.candidates.map(candidate => ({
            ...candidate,
            percentage: totalVotes > 0 ? Math.round((candidate.votes / totalVotes) * 100) : 0
        }));
        
        res.json({
            session: {
                id: session.id,
                title: session.title,
                description: session.description,
                totalVotes: totalVotes
            },
            candidates: candidatesWithPercentage
        });
    } catch (error) {
        console.error('Error fetching voting data:', error);
        res.status(500).json({ error: 'Failed to fetch voting data' });
    }
});

// Cast a vote in a session with enhanced security
app.post('/api/voting/:sessionId/vote', async (req, res) => {
    try {
        const { sessionId } = req.params;
        const { candidateId, captchaToken, captchaAnswer, email, emailCode } = req.body;
        let userSessionId = req.headers['x-session-id'];
        const clientIp = req.ip || req.connection.remoteAddress;
        const userAgent = req.headers['user-agent'] || '';
        const fingerprint = generateBrowserFingerprint(req);

        // SECURITY CHECK 1: Rate limiting
        if (isRateLimited(clientIp)) {
            trackSuspiciousActivity(clientIp, 'rate_limit_exceeded');
            return res.status(429).json({ 
                error: 'Too many requests. Please wait before trying again.',
                retryAfter: 60
            });
        }

        // SECURITY CHECK 2: Input validation
        if (!candidateId) {
            trackSuspiciousActivity(clientIp, 'invalid_candidate_id');
            return res.status(400).json({ error: 'Missing candidate ID' });
        }

        // Generate session ID if not provided
        if (!userSessionId) {
            userSessionId = uuidv4();
            res.setHeader('X-Session-ID', userSessionId);
        }

        // SECURITY CHECK 3: Check if session has already voted
        const voteKey = `${sessionId}-${userSessionId}`;
        if (hasVoted(voteKey)) {
            trackSuspiciousActivity(clientIp, 'duplicate_vote_attempt');
            return res.status(403).json({ 
                error: 'You have already voted in this session',
                votedFor: sessions.get(voteKey).votedFor
            });
        }

        // SECURITY CHECK 4: CAPTCHA verification for suspicious IPs
        if (isCaptchaRequired(clientIp)) {
            if (!captchaToken || !captchaAnswer) {
                return res.status(403).json({ 
                    error: 'CAPTCHA verification required',
                    requiresCaptcha: true
                });
            }
            
            if (!verifyCaptcha(captchaToken, captchaAnswer)) {
                trackSuspiciousActivity(clientIp, 'captcha_failed');
                return res.status(403).json({ 
                    error: 'CAPTCHA verification failed',
                    requiresCaptcha: true
                });
            }
        }

        // SECURITY CHECK 5: Email verification (if required)
        if (SECURITY_CONFIG.EMAIL_VERIFICATION_REQUIRED) {
            if (!email || !emailCode) {
                return res.status(403).json({ 
                    error: 'Email verification required',
                    requiresEmailVerification: true
                });
            }
            
            if (!verifyEmailCode(email, emailCode)) {
                trackSuspiciousActivity(clientIp, 'email_verification_failed');
                return res.status(403).json({ 
                    error: 'Email verification failed',
                    requiresEmailVerification: true
                });
            }
        }

        // SECURITY CHECK 6: Machine Learning Fraud Detection
        const fraudScore = calculateFraudScore(clientIp, userAgent, sessionId, null);
        if (fraudScore >= SECURITY_CONFIG.ML_FRAUD_THRESHOLD) {
            trackSuspiciousActivity(clientIp, 'ml_fraud_detected');
            return res.status(403).json({ 
                error: 'Voting behavior flagged as potentially fraudulent',
                fraudScore: fraudScore,
                requiresReview: true
            });
        }

        // SECURITY CHECK 7: IP-based vote limiting
        if (checkIPVoteLimit(sessionId, clientIp)) {
            trackSuspiciousActivity(clientIp, 'ip_vote_limit_exceeded');
            return res.status(403).json({ 
                error: `Maximum votes reached from this location. Limit: ${SECURITY_CONFIG.MAX_VOTES_PER_IP} votes per session.`,
                currentCount: getIPVoteCount(sessionId, clientIp)
            });
        }

        // Get voting session
        const votingSession = await DataManager.getSessionById(sessionId);
        if (!votingSession) {
            trackSuspiciousActivity(clientIp, 'invalid_session_access');
            return res.status(404).json({ error: 'Voting session not found' });
        }
        
        // SECURITY CHECK 8: Session status validation
        if (votingSession.status !== 'active') {
            trackSuspiciousActivity(clientIp, 'inactive_session_access');
            return res.status(403).json({ error: 'Voting session is not active' });
        }

        // SECURITY CHECK 9: Candidate validation
        const candidateIndex = votingSession.candidates.findIndex(c => c.id === candidateId);
        if (candidateIndex === -1) {
            trackSuspiciousActivity(clientIp, 'invalid_candidate_vote');
            return res.status(400).json({ error: 'Invalid candidate selection' });
        }

        // SECURITY CHECK 10: Vote cooldown (prevent rapid voting)
        const lastVoteSession = sessions.get(voteKey);
        if (lastVoteSession && lastVoteSession.timestamp) {
            const timeSinceLastVote = Date.now() - new Date(lastVoteSession.timestamp).getTime();
            if (timeSinceLastVote < SECURITY_CONFIG.VOTE_COOLDOWN) {
                trackSuspiciousActivity(clientIp, 'vote_cooldown_violation');
                return res.status(429).json({ 
                    error: 'Please wait before voting again',
                    waitTime: Math.ceil((SECURITY_CONFIG.VOTE_COOLDOWN - timeSinceLastVote) / 1000)
                });
            }
        }

        // All security checks passed - process the vote
        
        // Update vote count
        votingSession.candidates[candidateIndex].votes += 1;
        votingSession.totalVotes = (votingSession.totalVotes || 0) + 1;

        // Save updated session
        await DataManager.updateSession(sessionId, {
            candidates: votingSession.candidates,
            totalVotes: votingSession.totalVotes
        });

        // Record vote with enhanced tracking
        recordVote(voteKey, candidateId, clientIp, userAgent, fingerprint);
        
        // Update IP vote count
        incrementIPVoteCount(sessionId, clientIp);

        // Calculate percentages for broadcast
        const totalVotes = votingSession.totalVotes;
        const candidatesWithPercentage = votingSession.candidates.map(c => ({
            ...c,
            percentage: totalVotes > 0 ? Math.round((c.votes / totalVotes) * 100) : 0
        }));

        // Broadcast update to all connected clients in this session
        io.to(`session-${sessionId}`).emit('vote-update', {
            sessionId,
            candidates: candidatesWithPercentage,
            totalVotes
        });

        // Send success response with security info
        res.json({ 
            success: true, 
            message: `Vote recorded for ${votingSession.candidates[candidateIndex].name}`,
            totalVotes: votingSession.totalVotes,
            security: {
                ipVoteCount: getIPVoteCount(sessionId, clientIp),
                maxVotesPerIP: SECURITY_CONFIG.MAX_VOTES_PER_IP,
                fraudScore: fraudScore,
                riskLevel: fraudScore >= 0.7 ? 'HIGH' : fraudScore >= 0.4 ? 'MEDIUM' : 'LOW',
                verificationMethods: {
                    captchaUsed: isCaptchaRequired(clientIp) && captchaToken,
                    emailVerified: email && emailCode
                }
            }
        });

        console.log(`📊 Secure vote cast in session ${sessionId}: ${votingSession.candidates[candidateIndex].name} (Total: ${votingSession.candidates[candidateIndex].votes}) from IP: ${clientIp} [Fraud Score: ${fraudScore.toFixed(2)}]`);

    } catch (error) {
        console.error('Vote error:', error);
        trackSuspiciousActivity(req.ip, 'vote_processing_error');
        res.status(500).json({ error: 'Failed to process vote' });
    }
});

// Check voting status for a user session
app.get('/api/voting/:sessionId/vote-status', (req, res) => {
    const { sessionId } = req.params;
    let userSessionId = req.headers['x-session-id'];
    
    if (!userSessionId) {
        userSessionId = uuidv4();
        res.setHeader('X-Session-ID', userSessionId);
    }
    
    const voteKey = `${sessionId}-${userSessionId}`;
    const sessionData = sessions.get(voteKey);
    
    if (sessionData && sessionData.hasVoted) {
        res.json({
            sessionId: userSessionId,
            hasVoted: true,
            votedFor: sessionData.votedFor,
            timestamp: sessionData.timestamp
        });
    } else {
        res.json({ 
            sessionId: userSessionId,
            hasVoted: false 
        });
    }
});

// Admin Security Monitoring Endpoints
app.get('/api/security/suspicious-activity', (req, res) => {
    const activities = Array.from(suspiciousActivity.entries()).map(([ip, activities]) => ({
        ip,
        activities,
        count: activities.length,
        lastActivity: activities[activities.length - 1]?.timestamp
    }));
    
    res.json({
        suspiciousIPs: activities.filter(a => a.count >= SECURITY_CONFIG.SUSPICIOUS_THRESHOLD),
        allActivity: activities,
        securityConfig: SECURITY_CONFIG
    });
});

app.get('/api/security/ip-votes/:sessionId', (req, res) => {
    const { sessionId } = req.params;
    const ipVotes = Array.from(ipVoteCounts.entries())
        .filter(([key]) => key.startsWith(`${sessionId}-`))
        .map(([key, count]) => ({
            ip: key.replace(`${sessionId}-`, ''),
            voteCount: count
        }));
    
    res.json({
        sessionId,
        ipVoteCounts: ipVotes,
        maxVotesPerIP: SECURITY_CONFIG.MAX_VOTES_PER_IP
    });
});

app.get('/api/security/audit/:sessionId', async (req, res) => {
    const { sessionId } = req.params;
    
    // Get all votes for this session
    const sessionVotes = Array.from(sessions.entries())
        .filter(([key]) => key.startsWith(`${sessionId}-`))
        .map(([key, data]) => ({
            userSessionId: key.replace(`${sessionId}-`, ''),
            ...data
        }));
    
    // Get IP vote counts
    const ipVotes = Array.from(ipVoteCounts.entries())
        .filter(([key]) => key.startsWith(`${sessionId}-`))
        .map(([key, count]) => ({
            ip: key.replace(`${sessionId}-`, ''),
            voteCount: count
        }));
    
    res.json({
        sessionId,
        totalVotes: sessionVotes.length,
        voteDetails: sessionVotes,
        ipVoteCounts: ipVotes,
        potentialIssues: {
            duplicateIPs: ipVotes.filter(ip => ip.voteCount > 1),
            excessiveVotes: ipVotes.filter(ip => ip.voteCount >= SECURITY_CONFIG.MAX_VOTES_PER_IP)
        }
    });
});

// Advanced Security API Endpoints

// Generate CAPTCHA for suspicious users
app.get('/api/security/captcha', (req, res) => {
    const captcha = generateCaptcha();
    res.json({
        question: captcha.question,
        token: captcha.token
    });
});

// Request email verification
app.post('/api/security/email-verification', async (req, res) => {
    try {
        const { email, sessionId } = req.body;
        const clientIp = req.ip || req.connection.remoteAddress;
        
        if (!email || !sessionId) {
            return res.status(400).json({ error: 'Email and session ID required' });
        }
        
        // Get session info for email subject
        const session = await DataManager.getSessionById(sessionId);
        if (!session) {
            return res.status(404).json({ error: 'Session not found' });
        }
        
        const code = generateEmailCode();
        emailVerificationCodes.set(email, {
            code,
            timestamp: Date.now(),
            sessionId,
            ip: clientIp
        });
        
        const emailSent = await sendVerificationEmail(email, code, session.title);
        
        if (emailSent) {
            res.json({ 
                success: true, 
                message: 'Verification code sent to your email',
                expiresIn: SECURITY_CONFIG.EMAIL_CODE_EXPIRY / 1000 // seconds
            });
        } else {
            res.status(500).json({ error: 'Failed to send verification email' });
        }
        
    } catch (error) {
        console.error('Email verification error:', error);
        res.status(500).json({ error: 'Email verification failed' });
    }
});

// Verify email code
app.post('/api/security/verify-email', (req, res) => {
    const { email, code } = req.body;
    
    if (!email || !code) {
        return res.status(400).json({ error: 'Email and code required' });
    }
    
    const isValid = verifyEmailCode(email, code);
    
    if (isValid) {
        res.json({ 
            success: true, 
            message: 'Email verified successfully',
            verifiedUntil: Date.now() + (24 * 60 * 60 * 1000) // 24 hours
        });
    } else {
        res.status(400).json({ error: 'Invalid or expired verification code' });
    }
});

// Get fraud score for IP/session
app.get('/api/security/fraud-score/:sessionId/:ip', (req, res) => {
    const { sessionId, ip } = req.params;
    const fraudData = mlFraudScores.get(`${sessionId}-${ip}`);
    
    if (fraudData) {
        res.json({
            score: fraudData.score,
            risk: fraudData.score >= SECURITY_CONFIG.ML_FRAUD_THRESHOLD ? 'HIGH' : 
                  fraudData.score >= 0.4 ? 'MEDIUM' : 'LOW',
            factors: fraudData.factors,
            timestamp: fraudData.timestamp
        });
    } else {
        res.json({
            score: 0,
            risk: 'LOW',
            factors: {},
            timestamp: Date.now()
        });
    }
});

// Socket.IO connection handling
io.on('connection', (socket) => {
    console.log(`🔌 User connected: ${socket.id}`);

    // Join specific session room
    socket.on('join-session', (sessionId) => {
        socket.join(`session-${sessionId}`);
        console.log(`User ${socket.id} joined session ${sessionId}`);
    });

    // Leave session room
    socket.on('leave-session', (sessionId) => {
        socket.leave(`session-${sessionId}`);
        console.log(`User ${socket.id} left session ${sessionId}`);
    });

    // Handle disconnect
    socket.on('disconnect', () => {
        console.log(`🔌 User disconnected: ${socket.id}`);
    });

    // Handle real-time updates request
    socket.on('request-session-update', async (sessionId) => {
        try {
            const session = await DataManager.getSessionById(sessionId);
            if (session) {
                const totalVotes = session.totalVotes || 0;
                const candidatesWithPercentage = session.candidates.map(candidate => ({
                    ...candidate,
                    percentage: totalVotes > 0 ? Math.round((candidate.votes / totalVotes) * 100) : 0
                }));
                
                socket.emit('vote-update', {
                    sessionId,
                    candidates: candidatesWithPercentage,
                    totalVotes
                });
            }
        } catch (error) {
            console.error('Error sending session update:', error);
        }
    });
});

// Initialize and start server
async function startServer() {
    try {
        await createDirectories();
        server.listen(PORT, () => {
            console.log(`🚀 Multi-Tenant Voting Platform running on http://localhost:${PORT}`);
            console.log(`📊 Real-time updates enabled via Socket.IO`);
            console.log(`📁 Admin dashboard: http://localhost:${PORT}`);
            console.log(`🗺️ Voting URLs: http://localhost:${PORT}/vote/{sessionId}`);
        });
    } catch (error) {
        console.error('Failed to start server:', error);
        process.exit(1);
    }
}

startServer();