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
   - The voting interface will load automatically

## 🗳️ How It Works

### User Flow
1. User loads the webpage
2. System generates a unique session ID (stored in sessionStorage)
3. Frontend fetches initial candidate data via Socket.IO
4. User clicks "Vote" for their preferred candidate
5. System validates the vote and checks for duplicates
6. Vote is stored and broadcast to all connected clients
7. All users see updated vote counts in real-time

### API Endpoints

- `GET /api/votes` - Fetch current voting data
- `POST /api/vote` - Submit a vote
- `GET /api/vote-status/:sessionId` - Check if session has voted
- WebSocket events: `initialData`, `voteUpdate`

## 🔒 Security Features

### One Vote Per User Implementation
- **Primary**: Browser sessionStorage + server-side session tracking
- **Session ID**: Unique identifier per browser session
- **Server Validation**: Checks session status before accepting votes
- **Backup**: IP address logging for audit purposes

### Security Limitations & Trade-offs
- ✅ Prevents casual duplicate voting
- ✅ Simple to implement and understand
- ⚠️ Can be bypassed by clearing browser data
- ⚠️ Multiple users behind same NAT may be affected
- ⚠️ Not suitable for high-stakes elections

### Enhanced Security (Future Improvements)
- Email/phone verification
- JWT tokens with expiration
- Database storage with user accounts
- Rate limiting and CAPTCHA
- Cryptographic vote validation

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
mybuprojects/
├── index.html          # Frontend voting interface
├── server.js           # Backend server with Socket.IO
├── package.json        # Dependencies and scripts
├── votes.json          # Vote data storage (auto-generated)
└── README.md          # This documentation
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