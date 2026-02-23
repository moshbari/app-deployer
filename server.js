const express = require('express');
const { execSync, exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');

// ============================================
//  CONFIG
// ============================================
const PORT = process.env.PORT || 3000;
const HESTIA_USER = process.env.HESTIA_USER || 'heychatmate';
const PARENT_DOMAIN = process.env.PARENT_DOMAIN || 'heychatmate.com';
const DEPLOY_PASSWORD = process.env.DEPLOY_PASSWORD || 'changeme123';
const APP_DIR = path.join(__dirname, 'data');
const APPS_FILE = path.join(APP_DIR, 'apps.json');
const TEMPLATE_DIR = path.join(__dirname, 'template');
const WEB_ROOT = `/home/${HESTIA_USER}/web`;

// ============================================
//  APP SETUP
// ============================================
const app = express();
app.use(express.json({ limit: '10mb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

const sessions = new Map();
const buildLocks = new Map();

// ============================================
//  HELPERS
// ============================================
function loadApps() {
  if (!fs.existsSync(APPS_FILE)) return [];
  try { return JSON.parse(fs.readFileSync(APPS_FILE, 'utf8')); }
  catch { return []; }
}

function saveApps(apps) {
  fs.mkdirSync(APP_DIR, { recursive: true });
  fs.writeFileSync(APPS_FILE, JSON.stringify(apps, null, 2));
}

function sanitizeName(name) {
  return name.toLowerCase().replace(/[^a-z0-9-]/g, '').replace(/^-+|-+$/g, '').substring(0, 30);
}

function getDomain(appName) {
  return `${appName}.${PARENT_DOMAIN}`;
}

function getPublicHtml(domain) {
  return path.join(WEB_ROOT, domain, 'public_html');
}

function runCmd(cmd, opts = {}) {
  try {
    return { success: true, output: execSync(cmd, { encoding: 'utf8', timeout: 120000, ...opts }).trim() };
  } catch (e) {
    return { success: false, output: e.stderr || e.stdout || e.message };
  }
}

function log(msg) {
  const ts = new Date().toISOString();
  console.log(`[${ts}] ${msg}`);
}

// ============================================
//  AUTH MIDDLEWARE
// ============================================
function auth(req, res, next) {
  const token = req.cookies?.deploy_token || req.headers.authorization?.replace('Bearer ', '');
  if (!token || !sessions.has(token)) {
    return res.status(401).json({ error: 'Not logged in' });
  }
  next();
}

// ============================================
//  AUTH ROUTES
// ============================================
app.post('/api/login', (req, res) => {
  const { password } = req.body;
  if (password !== DEPLOY_PASSWORD) {
    return res.status(401).json({ error: 'Wrong password' });
  }
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { created: Date.now() });
  res.cookie('deploy_token', token, { httpOnly: true, sameSite: 'strict', maxAge: 30 * 24 * 60 * 60 * 1000 });
  res.json({ success: true });
});

app.post('/api/logout', (req, res) => {
  const token = req.cookies?.deploy_token;
  if (token) sessions.delete(token);
  res.clearCookie('deploy_token');
  res.json({ success: true });
});

app.get('/api/auth-check', (req, res) => {
  const token = req.cookies?.deploy_token;
  res.json({ authenticated: !!(token && sessions.has(token)) });
});

// ============================================
//  CODE VALIDATION
// ============================================
function validateCode(code) {
  if (!code || code.trim().length === 0) {
    return { valid: false, error: 'Code is empty' };
  }
  if (code.trimStart().startsWith('<!DOCTYPE') || code.trimStart().startsWith('<html')) {
    return { valid: false, error: 'You pasted HTML, not React code. In Claude, tap the Copy Code button on the artifact instead.' };
  }
  if (!code.includes('export default') && !code.includes('export {')) {
    return { valid: false, error: 'Code must have an export default. Make sure you copied the full React component.' };
  }
  return { valid: true };
}

// ============================================
//  APP ROUTES
// ============================================

// List all apps
app.get('/api/apps', auth, (req, res) => {
  res.json(loadApps());
});

// Deploy new app
app.post('/api/apps', auth, async (req, res) => {
  const { name: rawName, code, title } = req.body;
  const name = sanitizeName(rawName || '');

  if (!name) return res.status(400).json({ error: 'App name is required' });
  if (!code) return res.status(400).json({ error: 'Code is required' });
  if (name.length < 2) return res.status(400).json({ error: 'Name too short (min 2 chars)' });

  // Validate code
  const validation = validateCode(code);
  if (!validation.valid) {
    return res.status(400).json({ error: validation.error });
  }

  const apps = loadApps();
  if (apps.find(a => a.name === name)) {
    return res.status(400).json({ error: `App "${name}" already exists. Use update instead.` });
  }

  if (buildLocks.has(name)) {
    return res.status(409).json({ error: 'Build already in progress' });
  }

  buildLocks.set(name, true);
  const domain = getDomain(name);
  const buildDir = `/tmp/deployer-${name}-${Date.now()}`;

  try {
    log(`Deploying new app: ${name} (code length: ${code.length}) → ${domain}`);

    // 1. Build the React app
    log('Building...');
    const buildResult = buildApp(buildDir, code, title || name);
    if (!buildResult.success) {
      log('Build error: ' + buildResult.output);
      return res.status(500).json({ error: 'Build failed', details: buildResult.output });
    }

    // 2. Create domain in HestiaCP
    log('Creating domain...');
    const domainResult = createDomain(domain);
    if (!domainResult.success) {
      return res.status(500).json({ error: 'Domain creation failed', details: domainResult.output });
    }

    // 3. Copy build to public_html
    log('Deploying files...');
    const deployResult = deployFiles(buildDir, domain);
    if (!deployResult.success) {
      return res.status(500).json({ error: 'Deploy failed', details: deployResult.output });
    }

    // 4. Setup SSL (non-blocking)
    log('Setting up SSL...');
    setupSSL(domain);

    // 5. Save app record
    apps.push({
      name,
      domain,
      title: title || name,
      url: `https://${domain}`,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      deployCount: 1,
    });
    saveApps(apps);

    log(`✅ App deployed: https://${domain}`);
    res.json({ success: true, url: `https://${domain}`, domain });

  } catch (e) {
    log(`❌ Deploy failed: ${e.message}`);
    res.status(500).json({ error: e.message });
  } finally {
    buildLocks.delete(name);
    runCmd(`rm -rf ${buildDir}`);
  }
});

// Update existing app
app.put('/api/apps/:name', auth, (req, res) => {
  const { name } = req.params;
  const { code, title } = req.body;

  if (!code) return res.status(400).json({ error: 'Code is required' });

  // Validate code
  const validation = validateCode(code);
  if (!validation.valid) {
    return res.status(400).json({ error: validation.error });
  }

  const apps = loadApps();
  const appIndex = apps.findIndex(a => a.name === name);
  if (appIndex === -1) return res.status(404).json({ error: 'App not found' });

  if (buildLocks.has(name)) {
    return res.status(409).json({ error: 'Build already in progress' });
  }

  buildLocks.set(name, true);
  const domain = getDomain(name);
  const buildDir = `/tmp/deployer-${name}-${Date.now()}`;

  try {
    log(`Updating app: ${name} (code length: ${code.length})`);

    const buildResult = buildApp(buildDir, code, title || apps[appIndex].title);
    if (!buildResult.success) {
      log('Build error: ' + buildResult.output);
      return res.status(500).json({ error: 'Build failed', details: buildResult.output });
    }

    const deployResult = deployFiles(buildDir, domain);
    if (!deployResult.success) {
      return res.status(500).json({ error: 'Deploy failed', details: deployResult.output });
    }

    apps[appIndex].updatedAt = new Date().toISOString();
    apps[appIndex].deployCount = (apps[appIndex].deployCount || 0) + 1;
    if (title) apps[appIndex].title = title;
    saveApps(apps);

    log(`✅ App updated: https://${domain}`);
    res.json({ success: true, url: `https://${domain}` });

  } catch (e) {
    log(`❌ Update failed: ${e.message}`);
    res.status(500).json({ error: e.message });
  } finally {
    buildLocks.delete(name);
    runCmd(`rm -rf ${buildDir}`);
  }
});

// Delete app
app.delete('/api/apps/:name', auth, (req, res) => {
  const { name } = req.params;
  const apps = loadApps();
  const appIndex = apps.findIndex(a => a.name === name);
  if (appIndex === -1) return res.status(404).json({ error: 'App not found' });

  const domain = getDomain(name);

  try {
    log(`Deleting app: ${name}`);
    runCmd(`sudo /usr/local/hestia/bin/v-delete-web-domain ${HESTIA_USER} ${domain}`);
    apps.splice(appIndex, 1);
    saveApps(apps);
    log(`✅ App deleted: ${name}`);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Get single app + its code
app.get('/api/apps/:name', auth, (req, res) => {
  const { name } = req.params;
  const apps = loadApps();
  const appData = apps.find(a => a.name === name);
  if (!appData) return res.status(404).json({ error: 'App not found' });

  const codePath = path.join(APP_DIR, 'code', `${name}.jsx`);
  let code = '';
  try { code = fs.readFileSync(codePath, 'utf8'); } catch {}

  res.json({ ...appData, code });
});

// ============================================
//  BUILD & DEPLOY FUNCTIONS
// ============================================
function buildApp(buildDir, code, title) {
  // Copy template
  runCmd(`cp -r ${TEMPLATE_DIR} ${buildDir}`);

  // Write user's code as App.jsx
  fs.writeFileSync(path.join(buildDir, 'src', 'App.jsx'), code);

  // Update title in index.html
  const htmlPath = path.join(buildDir, 'index.html');
  let html = fs.readFileSync(htmlPath, 'utf8');
  html = html.replace('<title>My App</title>', `<title>${title}</title>`);
  fs.writeFileSync(htmlPath, html);

  // Build with Vite
  const result = runCmd(`cd ${buildDir} && npm run build 2>&1`, { env: { ...process.env, NODE_ENV: 'production' } });
  if (!result.success) {
    log('Build error: ' + result.output);
  }
  return result;
}

function createDomain(domain) {
  const check = runCmd(`sudo /usr/local/hestia/bin/v-list-web-domain ${HESTIA_USER} ${domain} 2>/dev/null`);
  if (check.success) {
    log(`Domain ${domain} already exists, skipping creation`);
    return { success: true, output: 'exists' };
  }

  const result = runCmd(`sudo /usr/local/hestia/bin/v-add-web-domain ${HESTIA_USER} ${domain}`);
  return result;
}

function setupSSL(domain) {
  setTimeout(() => {
    const sslResult = runCmd(`sudo /usr/local/hestia/bin/v-add-letsencrypt-domain ${HESTIA_USER} ${domain}`);
    if (sslResult.success) {
      runCmd(`sudo /usr/local/hestia/bin/v-add-web-domain-ssl-force ${HESTIA_USER} ${domain}`);
      log(`SSL enabled for ${domain}`);
    } else {
      log(`SSL setup delayed for ${domain} — DNS may not be ready yet`);
    }
  }, 3000);
}

function deployFiles(buildDir, domain) {
  const distDir = path.join(buildDir, 'dist');
  const publicHtml = getPublicHtml(domain);

  if (!fs.existsSync(distDir)) {
    return { success: false, output: 'dist/ folder not found after build' };
  }

  const result = runCmd(`rm -rf ${publicHtml}/* && cp -r ${distDir}/* ${publicHtml}/`);

  if (result.success) {
    runCmd(`sudo chown -R ${HESTIA_USER}:${HESTIA_USER} ${publicHtml}`);

    // Save code backup
    const codeSrc = path.join(buildDir, 'src', 'App.jsx');
    const codeDest = path.join(APP_DIR, 'code');
    fs.mkdirSync(codeDest, { recursive: true });
    const appName = domain.split('.')[0];
    fs.copyFileSync(codeSrc, path.join(codeDest, `${appName}.jsx`));
  }

  return result;
}

// ============================================
//  SPA FALLBACK
// ============================================
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ============================================
//  START
// ============================================
app.listen(PORT, '127.0.0.1', () => {
  log(`🚀 App Deployer running on port ${PORT}`);
  log(`   Dashboard: https://apps.${PARENT_DOMAIN}`);
  log(`   HestiaCP user: ${HESTIA_USER}`);
  log(`   Apps deploy to: *.${PARENT_DOMAIN}`);
});
