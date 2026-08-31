const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const OUT_DIR = path.join(ROOT, 'generated');

const ARTIFACTS = [
    'daily-status.json',
    'org-summary.json',
    'session-summary.json',
    'health-check.json'
];

function today() {
    return new Date().toISOString().slice(0, 10);
}

function readOptionalJSON(name) {
    try {
        const raw = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', name + '.json'), 'utf8'));
        if (Array.isArray(raw)) return raw;
        return Object.values(raw || {});
    } catch (e) {
        return null;
    }
}

function buildArtifacts() {
    const now = new Date();
    const date = now.toISOString().slice(0, 10);
    const generatedAt = now.toISOString();

    // Best-effort real data (present when workflow has committed data), else flexible fallback
    const organizations = readOptionalJSON('organizations') || [{ id: 'unknown', name: 'votesphere', active: true }];
    const sessions = readOptionalJSON('voting_sessions') || [{ id: 'unknown', title: 'voting', status: 'active', totalVotes: 0, candidates: [] }];
    const users = readOptionalJSON('users') || [{ username: 'admin', role: 'super_admin', mfaEnabled: false, isEmailVerified: true }];

    const activeSessions = sessions.filter(s => (s.status || '') === 'active').length;
    const totalVotes = sessions.reduce((sum, s) => sum + (Number(s.totalVotes) || 0), 0);

    const artifacts = {};

    artifacts['daily-status.json'] = {
        generatedAt,
        date,
        node: process.version,
        organizations: organizations.length,
        votingSessions: sessions.length,
        activeSessions,
        users: users.length,
        totalVotes,
        totalCandidates: sessions.reduce((sum, s) => sum + (Array.isArray(s.candidates) ? s.candidates.length : 0), 0)
    };

    artifacts['org-summary.json'] = {
        generatedAt,
        date,
        organizations: organizations.map(org => {
            const orgSessions = sessions.filter(s => (s.organizationId || s.orgId || '') === org.id);
            return {
                name: org.name || 'unknown',
                id: org.id,
                active: org.active,
                sessionCount: orgSessions.length,
                totalVotes: orgSessions.reduce((sum, s) => sum + (Number(s.totalVotes) || 0), 0)
            };
        })
    };

    artifacts['session-summary.json'] = {
        generatedAt,
        date,
        sessions: sessions.map(s => ({
            title: s.title || 'untitled',
            id: s.id,
            status: s.status || 'draft',
            organizationId: s.organizationId || s.orgId || null,
            totalVotes: Number(s.totalVotes) || 0,
            candidates: Array.isArray(s.candidates) ? s.candidates.length : 0
        }))
    };

    artifacts['health-check.json'] = {
        generatedAt,
        date,
        node: process.version,
        runner: 'github-actions',
        uptimeSeconds: Math.round(process.uptime()),
        users: {
            total: users.length,
            superAdmins: users.filter(u => (u.role || '') === 'super_admin').length,
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

function commitFile(cwd, file, message, isNewBranch) {
    execSync(`git add generated/${file}`, { cwd, stdio: 'inherit' });

    let changed = isNewBranch;
    if (!changed) {
        try {
            changed = execSync(`git diff --cached --name-only -- generated/${file}`, { cwd }).toString().trim() !== '';
        } catch (e) {
            changed = false;
        }
    }

    if (changed) {
        execSync(`git commit -m ${JSON.stringify(message)}`, { cwd, stdio: 'inherit' });
        return true;
    }
    return false;
}

function main() {
    if (!fs.existsSync(OUT_DIR)) fs.mkdirSync(OUT_DIR, { recursive: true });

    const date = today();
    const artifacts = buildArtifacts();
    const cwd = ROOT;

    // Determine if this is a fresh checkout where generated files do not yet exist
    let isNewBranch = false;
    try {
        isNewBranch = execSync('git ls-files generated/', { cwd }).toString().trim() === '';
    } catch (e) {
        isNewBranch = true;
    }

    let wroteAny = false;

    // Skip today's batch if already committed today
    try {
        const prev = JSON.parse(fs.readFileSync(path.join(OUT_DIR, 'daily-status.json'), 'utf8'));
        if (prev.date === date) {
            console.log('Daily status already generated today; skipping.');
            return;
        }
    } catch (e) {
        // No previous file -> proceed
    }

    for (const file of ARTIFACTS) {
        fs.writeFileSync(path.join(OUT_DIR, file), JSON.stringify(artifacts[file], null, 2) + '\n');
        const title = {
            'daily-status.json': 'Daily status',
            'org-summary.json': 'Organization summary',
            'session-summary.json': 'Voting session summary',
            'health-check.json': 'Runtime health check'
        }[file];
        const message = `${title}: ${date}`;
        try {
            if (commitFile(cwd, file, message, isNewBranch)) {
                console.log(`Created commit: ${message}`);
                wroteAny = true;
            } else {
                console.log(`No change for: ${file}`);
            }
        } catch (e) {
            console.error(`Failed to commit ${file}:`, e.message);
        }
    }

    if (wroteAny) {
        execSync('git push', { cwd, stdio: 'inherit' });
        console.log('Pushed daily artifact commits.');
    }
}

main();