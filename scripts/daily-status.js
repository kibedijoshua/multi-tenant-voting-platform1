const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const DATA_DIR = path.join(ROOT, 'data');
const OUT_DIR = path.join(ROOT, 'generated');

const ARTIFACTS = [
    {
        file: 'daily-status.json',
        title: 'Daily status'
    },
    {
        file: 'org-summary.json',
        title: 'Organization summary'
    },
    {
        file: 'session-summary.json',
        title: 'Voting session summary'
    },
    {
        file: 'health-check.json',
        title: 'Runtime health check'
    }
];

function readCollection(name) {
    try {
        const raw = JSON.parse(fs.readFileSync(path.join(DATA_DIR, name + '.json'), 'utf8'));
        if (Array.isArray(raw)) return raw;
        return Object.values(raw || {});
    } catch (e) {
        return [];
    }
}

function buildArtifacts() {
    const now = new Date();
    const date = now.toISOString().slice(0, 10);
    const generatedAt = now.toISOString();

    const organizations = readCollection('organizations');
    const sessions = readCollection('voting_sessions');
    const users = readCollection('users');
    const authSessions = readCollection('auth_sessions');
    const resetTokens = readCollection('reset_tokens');

    const activeSessions = sessions.filter(s => s.status === 'active').length;
    const totalVotes = sessions.reduce((sum, s) => sum + (Number(s.totalVotes) || 0), 0);
    const totalCandidates = sessions.reduce((sum, s) => sum + (Array.isArray(s.candidates) ? s.candidates.length : 0), 0);

    const artifacts = {};

    artifacts['daily-status.json'] = {
        generatedAt,
        date,
        node: process.version,
        organizations: organizations.length,
        votingSessions: sessions.length,
        activeSessions,
        users: users.length,
        authSessions: authSessions.length,
        totalVotes,
        totalCandidates,
        resetTokens: resetTokens.length
    };

    artifacts['org-summary.json'] = {
        generatedAt,
        date,
        organizations: organizations.map(org => {
            const orgSessions = sessions.filter(s => (s.organizationId || s.orgId) === org.id);
            return {
                name: org.name,
                id: org.id,
                active: org.active,
                sessionCount: orgSessions.length,
                totalVotes: orgSessions.reduce((sum, s) => sum + (Number(s.totalVotes) || 0), 0),
                candidates: orgSessions.reduce((sum, s) => sum + (Array.isArray(s.candidates) ? s.candidates.length : 0), 0)
            };
        })
    };

    artifacts['session-summary.json'] = {
        generatedAt,
        date,
        sessions: sessions.map(s => ({
            title: s.title,
            id: s.id,
            status: s.status,
            organizationId: s.organizationId || s.orgId,
            totalVotes: Number(s.totalVotes) || 0,
            candidates: Array.isArray(s.candidates) ? s.candidates.length : 0
        }))
    };

    artifacts['health-check.json'] = {
        generatedAt,
        date,
        node: process.version,
        uptimeSeconds: Math.round(process.uptime()),
        users: {
            total: users.length,
            superAdmins: users.filter(u => u.role === 'super_admin').length,
            orgAdmins: users.filter(u => u.role === 'org_admin').length,
            voters: users.filter(u => u.role === 'voter').length
        },
        auth: {
            activeSessions: authSessions.length,
            mfaEnabled: users.filter(u => u.mfaEnabled).length,
            verified: users.filter(u => u.isEmailVerified).length
        },
        platform: {
            organizations: organizations.length,
            votingSessions: sessions.length,
            activeSessions,
            totalVotes
        }
    };

    return artifacts;
}

function commitFile(cwd, file, message) {
    execSync(`git add generated/${file}`, { cwd, stdio: 'inherit' });

    let staged;
    try {
        staged = execSync(`git diff --cached --name-only -- generated/${file}`, { cwd }).toString().trim();
    } catch (e) {
        staged = '';
    }

    if (staged) {
        execSync(`git commit -m ${JSON.stringify(message)}`, { cwd, stdio: 'inherit' });
        return true;
    }
    return false;
}

function main() {
    if (!fs.existsSync(OUT_DIR)) fs.mkdirSync(OUT_DIR, { recursive: true });

    const date = new Date().toISOString().slice(0, 10);
    const artifacts = buildArtifacts();

    // Skip if already generated today (avoids duplicate same-day replays)
    const statusFile = path.join(OUT_DIR, 'daily-status.json');
    let committedToday = false;
    try {
        const prev = JSON.parse(fs.readFileSync(statusFile, 'utf8'));
        committedToday = prev.date === date;
    } catch (e) { /* first run */ }
    if (committedToday) {
        console.log('Artifacts already generated for today; skipping.');
        return;
    }

    const cwd = ROOT;
    let wroteAny = false;

    for (const a of ARTIFACTS) {
        const content = artifacts[a.file];
        fs.writeFileSync(path.join(OUT_DIR, a.file), JSON.stringify(content, null, 2) + '\n');
        const message = `${a.title}: ${date}`;
        try {
            const didCommit = commitFile(cwd, a.file, message);
            if (didCommit) {
                console.log(`Created commit: ${message}`);
                wroteAny = true;
            } else {
                console.log(`No change for: ${a.file}`);
            }
        } catch (e) {
            console.error(`Failed to commit ${a.file}:`, e.message);
        }
    }

    if (wroteAny) {
        try {
            execSync('git push', { cwd, stdio: 'inherit' });
            console.log('Pushed all daily artifact commits.');
        } catch (e) {
            console.error('Push failed:', e.message);
        }
    }
}

main();
