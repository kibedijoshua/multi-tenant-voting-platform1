const sqlite3 = require('sqlite3').verbose();
const path = require('path');

class Database {
    constructor() {
        this.db = new sqlite3.Database(path.join(__dirname, 'voting.db'));
        this.init();
    }

    init() {
        // Create candidates table
        this.db.run(`
            CREATE TABLE IF NOT EXISTS candidates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT,
                votes INTEGER DEFAULT 0
            )
        `);

        // Create sessions table for vote tracking
        this.db.run(`
            CREATE TABLE IF NOT EXISTS vote_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT UNIQUE NOT NULL,
                ip_address TEXT NOT NULL,
                user_agent TEXT,
                has_voted BOOLEAN DEFAULT FALSE,
                voted_for INTEGER,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (voted_for) REFERENCES candidates (id)
            )
        `);

        // Insert default candidates if none exist
        this.db.get("SELECT COUNT(*) as count FROM candidates", (err, row) => {
            if (err) {
                console.error('Error checking candidates:', err);
                return;
            }
            
            if (row.count === 0) {
                const candidates = [
                    { name: 'John Doe', description: 'Experienced leader with vision for change' },
                    { name: 'Jane Smith', description: 'Progressive candidate focused on innovation' },
                    { name: 'Bob Johnson', description: 'Community advocate with proven track record' },
                    { name: 'Alice Brown', description: 'Environmental champion and policy expert' }
                ];

                const stmt = this.db.prepare("INSERT INTO candidates (name, description) VALUES (?, ?)");
                candidates.forEach(candidate => {
                    stmt.run(candidate.name, candidate.description);
                });
                stmt.finalize();
                
                console.log('Default candidates initialized');
            }
        });
    }

    // Get all candidates with their vote counts
    getCandidates(callback) {
        this.db.all("SELECT * FROM candidates ORDER BY id", callback);
    }

    // Get candidate by ID
    getCandidate(id, callback) {
        this.db.get("SELECT * FROM candidates WHERE id = ?", [id], callback);
    }

    // Check if session has already voted
    checkVoteSession(sessionId, callback) {
        this.db.get(
            "SELECT * FROM vote_sessions WHERE session_id = ?", 
            [sessionId], 
            callback
        );
    }

    // Create or update vote session
    createVoteSession(sessionId, ipAddress, userAgent, callback) {
        this.db.run(
            "INSERT OR REPLACE INTO vote_sessions (session_id, ip_address, user_agent) VALUES (?, ?, ?)",
            [sessionId, ipAddress, userAgent],
            callback
        );
    }

    // Record a vote
    recordVote(sessionId, candidateId, callback) {
        const db = this.db;
        
        db.serialize(() => {
            db.run("BEGIN TRANSACTION");
            
            // Update vote session
            db.run(
                "UPDATE vote_sessions SET has_voted = TRUE, voted_for = ? WHERE session_id = ?",
                [candidateId, sessionId],
                function(err) {
                    if (err) {
                        db.run("ROLLBACK");
                        return callback(err);
                    }
                }
            );
            
            // Increment candidate vote count
            db.run(
                "UPDATE candidates SET votes = votes + 1 WHERE id = ?",
                [candidateId],
                function(err) {
                    if (err) {
                        db.run("ROLLBACK");
                        return callback(err);
                    }
                    
                    db.run("COMMIT");
                    callback(null, { changes: this.changes });
                }
            );
        });
    }

    // Get voting statistics
    getVotingStats(callback) {
        this.db.all(`
            SELECT 
                c.id,
                c.name,
                c.description,
                c.votes,
                COALESCE(total_votes.total, 0) as total_votes,
                CASE 
                    WHEN COALESCE(total_votes.total, 0) = 0 THEN 0 
                    ELSE ROUND((c.votes * 100.0) / total_votes.total, 2) 
                END as percentage
            FROM candidates c
            CROSS JOIN (SELECT SUM(votes) as total FROM candidates) total_votes
            ORDER BY c.votes DESC, c.id
        `, callback);
    }

    close() {
        this.db.close();
    }
}

module.exports = Database;