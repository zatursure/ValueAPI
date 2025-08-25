require('dotenv').config();
const express = require('express');
const fs = require('fs');
const path = require('path');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const app = express();
const PORT = process.env.PORT || 3000;
const TOKEN = process.env.TOKEN;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const adminSesList = {};
app.use(cookieParser());

app.get(['/.env', '/config.json'], (req, res) => {
    res.status(403).send('扫你🐎呢');
});

const adminSes = new Set();
function createSession() {
    const sid = crypto.randomBytes(16).toString('hex');
    adminSes.add(sid);
    return sid;
}

function getSession(req, res) {
    let sid = req.cookies && req.cookies.captcha_sid;
    if (!sid || !adminSesList[sid]) {
        sid = crypto.randomBytes(12).toString('hex');
        adminSesList[sid] = {};
        res.cookie('captcha_sid', sid, { httpOnly: true });
    }
    return adminSesList[sid];
}

let configCache = null;
let cacheMtime = 0;
const configPath = path.join(__dirname, 'config.json');
function loadConfig() {
    try {
        const stat = fs.statSync(configPath);
        if (!configCache || stat.mtimeMs !== cacheMtime) {
            const data = fs.readFileSync(configPath, 'utf-8');
            configCache = JSON.parse(data);
            cacheMtime = stat.mtimeMs;
        }
        return configCache;
    } catch (err) {
        console.error('读取 config.json 失败:', err);
        configCache = { variables: [] };
        return configCache;
    }
}

function saveConfig(config) {
    try {
        fs.writeFileSync(configPath, JSON.stringify(config, null, 2), 'utf-8');
        configCache = config;
        cacheMtime = fs.statSync(configPath).mtimeMs;
        return true;
    } catch (err) {
        console.error('保存配置失败:', err);
        return false;
    }
}

// 读取config.json
function getSettings() { return loadConfig().variables; }

function log(level, message) {
    const now = new Date();
    const pad = n => n.toString().padStart(2, '0');
    const timeStr = `${now.getFullYear()}/${pad(now.getMonth() + 1)}/${pad(now.getDate())}/${pad(now.getHours())}:${pad(now.getMinutes())}`;
    console.log(`[${level}][${timeStr}] ${message}`);
}

function logInfo(message) {
    log('INFO', message);
}

function logError(message) {
    log('ERROR', message);
}

function ckToken(req, res, next) {
    const token = req.query.token;
    if (token === TOKEN) return next();
    logError(`身份验证失败，IP: ${req.ip}`);
    return res.status(401).json({ error: 'Invalid or missing token' });
}

function ckAuth(req, res, next) {
    const sid = req.cookies && req.cookies.adminsid;
    if (sid && adminSes.has(sid)) return next();
    return res.redirect('/admin/login');
}

app.get('/get', ckToken, (req, res) => {
    const name = req.query.name;
    if (!name) {
        logError('查询变量失败：缺少变量名');
        return res.status(400).json({ error: 'Missing variable name' });
    }
    const variable = getSettings().find(v => v.name === name);
    if (!variable) {
        logError(`查询变量失败：${name} 不存在`);
        return res.status(404).json({ error: 'Variable not found' });
    }
    logInfo(`查询变量：${name}，值：${variable.value}，IP: ${req.ip}`);
    res.send(String(variable.value));
});

app.post('/set', ckToken, (req, res) => {
    const name = req.query.name;
    const value = req.query.value;
    if (!name || typeof value === 'undefined') {
        logError('修改变量失败：缺少 name 或 value');
        return res.status(400).json({ error: 'Missing name or value' });
    }
    const config = loadConfig();
    const variable = config.variables.find(v => v.name === name);
    if (!variable) {
        logError(`修改变量失败：${name} 不存在`);
        return res.status(404).json({ error: 'Variable not found' });
    }
    const oldValue = variable.value;
    variable.value = String(value);
    if (!saveConfig(config)) {
        logError(`保存变量失败：${name}`);
        return res.status(500).json({ error: '保存失败' });
    }
    logInfo(`修改变量：${name}，原值：${oldValue}，新值：${value}，IP: ${req.ip}`);
    res.json({ success: true, variable });
});

app.get('/admin/login', (req, res) => {
    res.send(`
        <html><head><title>ValueAPI - 管理面板登录</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>body{background:#f7f7f7;} .login-panel{max-width:340px;margin:80px auto;padding:32px 24px;background:#fff;border-radius:8px;box-shadow:0 2px 8px #0001;}</style>
        </head><body>
        <div class="login-panel">
        <h4 class="mb-4">管理面板登录</h4>
        <form method="POST" action="/admin/login">
            <div class="mb-3"><input type="password" class="form-control" name="password" placeholder="密码" required /></div>
            <button type="submit" class="btn btn-primary w-100">登录</button>
        </form>
        </div>
        </body></html>
    `);
});

app.post('/admin/login', express.urlencoded({ extended: false }), (req, res) => {
    const { password } = req.body;
    if (password === ADMIN_PASSWORD) {
        const sid = createSession();
        res.cookie('adminsid', sid, { httpOnly: true });
        logInfo(`管理登录成功，IP: ${req.ip}`);
        return res.redirect('/admin');
    }
    logError(`管理登录失败，IP: ${req.ip}`);
    return res.send('<script>alert("密码错误");location.href="/admin/login"</script>');
});

app.get('/admin', ckAuth, (req, res) => {
    logInfo(`访问管理面板，IP: ${req.ip}`);
    const variables = getSettings();
    let rows = variables.map(v => `
        <tr>
            <td>${v.name}</td>
            <td>
                <form method="POST" action="/admin/edit" class="d-inline-flex align-items-center">
                    <input type="hidden" name="name" value="${v.name}" />
                    <input name="value" value="${v.value}" class="form-control form-control-sm me-2" style="width:120px;" />
                    <button type="submit" class="btn btn-sm btn-outline-primary">修改</button>
                </form>
            </td>
            <td>
                <form method="POST" action="/admin/delete" class="d-inline">
                    <input type="hidden" name="name" value="${v.name}" />
                    <button type="submit" class="btn btn-sm btn-outline-danger" onclick="return confirm('确定删除？')">删除</button>
                </form>
            </td>
        </tr>
    `).join('');
    res.send(`
        <html><head><title>ValueAPI - 管理面板</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>body{background:#f7f7f7;} .panel{background:#fff;padding:24px;border-radius:8px;box-shadow:0 2px 8px #0001;max-width:700px;margin:40px auto;}</style>
        </head><body>
        <div class="panel">
        <h2 class="mb-4">变量管理</h2>
        <table class="table table-bordered align-middle">
            <thead class="table-light"><tr><th>变量名</th><th>值</th><th>操作</th></tr></thead>
            <tbody>${rows}</tbody>
        </table>
        <h5 class="mt-4">添加变量</h5>
        <form method="POST" action="/admin/add" class="row g-2 mb-3">
            <div class="col-auto"><input name="name" class="form-control" placeholder="变量名" required /></div>
            <div class="col-auto"><input name="value" class="form-control" placeholder="值" required /></div>
            <div class="col-auto"><button type="submit" class="btn btn-success">添加</button></div>
        </form>
        <a href="/admin/logout" class="btn btn-link">退出登录</a>
        </div>
        </body></html>
    `);
});

app.get('/admin/logout', (req, res) => {
    const sid = req.cookies && req.cookies.adminsid;
    if (sid) adminSes.delete(sid);
    res.clearCookie('adminsid');
    logInfo(`管理登出，IP: ${req.ip}`);
    res.redirect('/admin/login');
});

app.post('/admin/edit', ckAuth, express.urlencoded({ extended: false }), (req, res) => {
    const { name, value } = req.body;
    if (!name || typeof value === 'undefined') {
        logError(`变量编辑失败：缺少 name 或 value，IP: ${req.ip}`);
        return res.send('缺少 name 或 value');
    }
    const config = loadConfig();
    const variable = config.variables.find(v => v.name === name);
    if (!variable) {
        logError(`变量编辑失败：${name} 不存在，IP: ${req.ip}`);
        return res.send('变量不存在');
    }
    const oldValue = variable.value;
    variable.value = String(value);
    if (!saveConfig(config)) {
        logError(`变量编辑保存失败：${name}，IP: ${req.ip}`);
        return res.send('保存失败');
    }
    logInfo(`变量编辑：${name}，原值：${oldValue}，新值：${value}，IP: ${req.ip}`);
    res.redirect('/admin');
});

app.post('/admin/add', ckAuth, express.urlencoded({ extended: false }), (req, res) => {
    const { name, value } = req.body;
    if (!name || typeof value === 'undefined') {
        logError(`新增变量失败：缺少 name 或 value，IP: ${req.ip}`);
        return res.send('缺少 name 或 value');
    }
    const config = loadConfig();
    if (config.variables.find(v => v.name === name)) {
        logError(`新增变量失败：${name} 已存在，IP: ${req.ip}`);
        return res.send('变量已存在');
    }
    config.variables.push({ name, value: String(value) });
    if (!saveConfig(config)) {
        logError(`新增变量保存失败：${name}，IP: ${req.ip}`);
        return res.send('保存失败');
    }
    logInfo(`新增变量：${name}，值：${value}，IP: ${req.ip}`);
    res.redirect('/admin');
});

app.post('/admin/delete', ckAuth, express.urlencoded({ extended: false }), (req, res) => {
    const { name } = req.body;
    if (!name) {
        logError(`删除变量失败：缺少 name，IP: ${req.ip}`);
        return res.send('缺少 name');
    }
    const config = loadConfig();
    const idx = config.variables.findIndex(v => v.name === name);
    if (idx === -1) {
        logError(`删除变量失败：${name} 不存在，IP: ${req.ip}`);
        return res.send('变量不存在');
    }
    config.variables.splice(idx, 1);
    if (!saveConfig(config)) {
        logError(`删除变量保存失败：${name}，IP: ${req.ip}`);
        return res.send('保存失败');
    }
    logInfo(`删除变量：${name}，IP: ${req.ip}`);
    res.redirect('/admin');
});

app.get('/', (req, res) => {
    res.send(`
        <html>
        <head>
            <title>首页 - ValueAPI</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
            <style>
                body { background: #f7f7f7; }
                .main-panel { max-width: 700px; margin: 60px auto; background: #fff; border-radius: 8px; box-shadow: 0 2px 8px #0001; padding: 32px 28px; }
                code { background: #f5f5f5; padding: 2px 6px; border-radius: 4px; }
            </style>
        </head>
        <body>
            <div class="main-panel">
                <h2 class="mb-3">ValueAPI</h2>
                <p class="text-muted">一个轻量级的变量存储与管理接口，支持通过API接口进行变量的查询和修改，并通过一个简单的后台进行可视化修改</p>
                <hr>
                <h5>自带接口/文件说明</h5>
                <ul>
                    <li><b>查询变量：</b> <code>GET /get?name=变量名&token=你的Token</code></li>
                    <li><b>设置变量：</b> <code>POST /set?name=变量名&value=新值&token=你的Token</code></li>
                    <li><b>管理后台：</b> <a href="/admin">/admin</a></li>
                    <li><b>本地变量列表存储地址：</b> <a>config.json</a></li>
                    <li><b>全局变量存储地址(面板密码,token)：</b> <a>.env</a></li>
                </ul>
                <h6 class="mt-4">示例</h6>
                <pre class="bg-light p-2 rounded"><code>curl "http://你的IP:${PORT}/get?name=foo&token=你的Token"</code></pre>
                <pre class="bg-light p-2 rounded"><code>curl -X POST "http://你的IP:${PORT}/set?name=foo&value=bar&token=你的Token"</code></pre>
                <hr>
                <div class="text-muted small">Powered by ValueAPI & Made By Zatursure</div>
                <div class="text-muted small">Star this Project on Github (zatursure/ValueAPI)</div>
            </div>
        </body>
        </html>
    `);
});

// ValueAPI, 启动!
app.listen(PORT, () => {
    let version = '';
    try {
        const pkg = require('./package.json');
        version = pkg.version ? ` v${pkg.version}` : '';
    } catch (e) {
        version = '';
    }
    console.log(`|----------------------------------------------------------|`);
    console.log(`|---------------ValueAPI - Made By Zatursure---------------|`);
    console.log(`|-----Star this project on Github (zatursure/ValueAPI)-----|`);
    console.log(`|------------------Version: ${version}---------------------|`);
    console.log(`|----------------------------------------------------------|`);
    logInfo(`ValueAPI运行在 http://localhost:${PORT}${version}`);
});
