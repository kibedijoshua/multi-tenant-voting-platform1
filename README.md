# 🗳️ Multi-Tenant Voting Platform

A comprehensive online voting platform that allows organizations to create and manage their own voting sessions with advanced security features.

## ✨ Features

- **Multi-Tenant Architecture**: Organizations can create independent voting sessions
- **Advanced Security**: CAPTCHA, email verification, rate limiting, fraud detection
- **Real-Time Results**: Live vote counting with Socket.IO
- **Candidate Management**: Photo uploads, descriptions, and profiles
- **Session Management**: Draft → Active → Completed workflow
- **Admin Dashboard**: Comprehensive management interface
- **Public Voting Finder**: Easy discovery of voting sessions
- **Clickable Voting URLs**: Easy sharing with copy functionality

## 🚀 Quick Deploy

### Deploy to Render (Free)

1. **Fork/Clone this repository**
2. **Sign up at [Render.com](https://render.com)**
3. **Create a new Web Service**
4. **Connect your GitHub repository**
5. **Configure the following:**
   - Build Command: `npm install`
   - Start Command: `npm start`
   - Environment Variables:
     ```
     NODE_ENV=production
     EMAIL_USER=your-email@gmail.com (optional)
     EMAIL_PASS=your-app-password (optional)
     ```
6. **Deploy!** 🎉

### Deploy to Railway

1. **Sign up at [Railway.app](https://railway.app)**
2. **Deploy from GitHub**
3. **Add environment variables** (same as above)
4. **Deploy!** 🚀

### Deploy to Heroku

1. **Install Heroku CLI**
2. **Login to Heroku**: `heroku login`
3. **Create app**: `heroku create your-voting-app`
4. **Deploy**: `git push heroku main`
5. **Set environment variables**:
   ```bash
   heroku config:set NODE_ENV=production
   heroku config:set EMAIL_USER=your-email@gmail.com
   ```

## 🏗️ System Architecture

```
Browser Client ↔ Frontend (HTML/CSS/JS) ↔ Express.js Server ↔ JSON File Storage
                     ↕                         ↕
              Socket.IO Client          Socket.IO Server
                     ↕                         ↕
            Real-time Vote Updates    Live Broadcasting
```

## 🛠️ Technology Stack

- **Frontend**: HTML5, CSS3, Vanilla JavaScript, Socket.IO Client
- **Backend**: Node.js, Express.js, Socket.IO
- **Data Storage**: JSON file (`votes.json`)
- **Real-time Communication**: WebSockets via Socket.IO
- **Session Management**: In-memory sessions with UUID

## 📦 Installation & Setup

1. **Install Dependencies**
   ```bash
   npm install
   ```

2. **Start the Server**
   ```bash
   npm start
   # or
   node server.js
   ```

3. **Access the Application**
   - Open your browser and go to: `http://localhost:3000`
   - You'll be redirected to the login page automatically
   - On first start, a default super admin is created (credentials printed to the console).
     Set `DEFAULT_ADMIN_PASSWORD` in your environment to use your own password.
   - Sign in to access the admin dashboard.

## 🗳️ How It Works

### User Flow
1. Admin signs in at `/` (redirected to `/login` if not authenticated)
2. Super admin creates organizations; org admins create voting sessions
3. Sessions follow a Draft → Active → Completed workflow
4. When active, a clickable voting URL (`/vote/{sessionId}`) is generated and shared
5. Voters open the URL, review candidates, and cast a single vote
6. Real-time vote counts update via Socket.IO for all connected clients

### API Endpoints

**Authentication:**
- `POST /api/auth/register` - Register a new user
- `POST /api/auth/login` - Login (supports MFA code)
- `POST /api/auth/logout` - Logout
- `GET /api/auth/me` - Get current user
- `POST /api/auth/mfa/setup|enable|disable` - Two-factor authentication
- `POST /api/auth/change-password` - Change password

**Admin (requires auth):**
- `GET/POST /api/organizations` - Manage organizations
- `GET/POST /api/sessions` - Manage voting sessions
- `POST/DELETE /api/sessions/:id/candidates` - Manage candidates
- `PATCH /api/sessions/:id/status` - Change session status
- `GET /api/security/*` - Security monitoring / audit

**Public voting:**
- `GET /api/voting/:sessionId` - Fetch current voting data
- `POST /api/voting/:sessionId/vote` - Submit a vote
- `GET /api/voting/:sessionId/vote-status` - Check if already voted
- WebSocket events: `join-session`, `request-session-update`, `vote-update`

## 🔒 Security Features

- **Authentication**: JWT + session-based login, bcrypt password hashing, account lockout
- **Multi-Factor Authentication**: TOTP (Google Authenticator) with QR code setup
- **One Vote Per User**: Browser session + server-side session tracking + IP limiting
- **CAPTCHA**: Math-based CAPTCHA for flagged IPs
- **Email Verification**: Optional 6-digit code verification
- **Fraud Detection**: ML-style scoring based on voting patterns
- **Rate Limiting**: Per-IP limits on login and API endpoints

## 📊 Data Structure

### Candidate Object
```javascript
{
  id: 1,
  name: "John Doe",
  description: "Experienced leader with vision",
  photo: "https://via.placeholder.com/150x150/4CAF50/white?text=JD",
  votes: 0
}
```

### Vote Data Storage (`votes.json`)
```javascript
{
  candidates: [
    { id: 1, name: "John Doe", description: "...", photo: "...", votes: 0 },
    { id: 2, name: "Jane Smith", description: "...", photo: "...", votes: 0 },
    { id: 3, name: "Mike Johnson", description: "...", photo: "...", votes: 0 }
  ],
  totalVotes: 0,
  lastUpdated: "2024-01-15T10:30:00Z"
}
```

### Session Management (In-Memory)
```javascript
{
  sessionId: {
    hasVoted: true,
    votedFor: 1,
    timestamp: "2024-01-15T10:30:00Z",
    ip: "192.168.1.1"
  }
}
```

## 🌐 Real-Time Communication

### Socket.IO Events

**Client → Server:**
- `connection` - New client connects
- `requestUpdate` - Request current vote data

**Server → Client:**
- `initialData` - Send initial voting data
- `voteUpdate` - Broadcast updated vote counts

### WebSocket Flow
1. Client connects to server
2. Server sends initial voting data
3. When vote is cast, server broadcasts update to all clients
4. All connected clients update their displays instantly

## 🎨 UI/UX Features

- **Gradient Backgrounds**: Modern visual appeal
- **Progress Bars**: Visual representation of vote distribution
- **Pulse Animations**: Connection status indicators
- **Responsive Grid**: Adapts to different screen sizes
- **Status Messages**: Success/error feedback
- **Loading States**: Smooth user experience
- **Hover Effects**: Interactive candidate cards

## 🐛 Troubleshooting

### Common Issues

1. **Server Won't Start**
   - Ensure Node.js is installed: `node --version`
   - Check if port 3000 is available
   - Verify all dependencies are installed: `npm install`

2. **Real-time Updates Not Working**
   - Check browser console for WebSocket errors
   - Ensure firewall allows WebSocket connections
   - Try refreshing the page

3. **Votes Not Saving**
   - Check server console for error messages
   - Verify write permissions for `votes.json`
   - Ensure sufficient disk space

### Development Mode
```bash
# Run with auto-restart (if nodemon is installed)
npm install -g nodemon
nodemon server.js
```

## 📁 File Structure

```
multi-tenant-voting-platform/
├── server.js            # Backend server (Express + Socket.IO + auth routes)
├── auth.js              # Authentication manager (register, login, MFA, password reset)
├── auth-middleware.js    # Auth middleware (roles, rate limiting, CSRF, security headers)
├── admin.html           # Admin dashboard (protected, requires login)
├── login.html           # Login page
├── register.html        # Registration page
├── vote.html            # Voting interface
├── enhanced-vote.html   # Enhanced secure voting interface
├── public-voting.html   # Public voting finder
├── package.json
├── votes.json           # Auto-generated (legacy, unused)
└── README.md
```

## 🔧 Customization

### Adding New Candidates
Edit the `initialData` object in `server.js`:
```javascript
{
  id: 4,
  name: "New Candidate",
  description: "Candidate description",
  photo: "https://via.placeholder.com/150x150/COLOR/white?text=NC",
  votes: 0
}
```

### Styling Changes
- Modify CSS variables in `index.html`
- Update gradient colors and animations
- Customize candidate card layouts

### Security Enhancements
- Add rate limiting middleware
- Implement JWT authentication
- Add HTTPS support
- Database integration

## 📊 Performance Considerations

- **JSON File Storage**: Suitable for small-scale voting (< 1000 votes)
- **In-Memory Sessions**: Resets on server restart
- **WebSocket Connections**: Handles ~1000 concurrent users
- **Scaling**: Consider Redis for sessions, PostgreSQL for data

## 🎯 Use Cases

- **Educational**: Student government elections
- **Corporate**: Team decision making
- **Community**: Local organization voting
- **Events**: Real-time audience polling
- **Demos**: Proof-of-concept voting systems

## ⚡ Quick Start Commands

```bash
# Install and run
npm install && npm start

# Access the application
# Open http://localhost:3000 in your browser

# Stop the server
# Press Ctrl+C in the terminal
```

## 📝 License

MIT License - Feel free to use and modify for your projects.

---

**Created with ❤️ for simple, secure, real-time voting experiences!**