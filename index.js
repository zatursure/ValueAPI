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

app.get(['/.env', '/config.json', '/history.json', '/settings.json'], (req, res) => {
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
function initConfig() {
    return {
        groups: [{ id: 'default', name: '默认分组' }],
        variables: []
    };
}

function loadConfig() {
    try {
        const stat = fs.statSync(configPath);
        if (!configCache || stat.mtimeMs !== cacheMtime) {
            const data = fs.readFileSync(configPath, 'utf-8');
            configCache = JSON.parse(data);
            // 兼容旧数据
            if (!configCache.groups) {
                configCache.groups = [{ id: 'default', name: '默认分组' }];
                configCache.variables.forEach(v => v.groupId = 'default');
            }
            cacheMtime = stat.mtimeMs;
        }
        return configCache;
    } catch (err) {
        console.error('读取 config.json 失败:', err);
        configCache = initConfig();
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
    const settings = loadSystemSettings();
    if (settings.tokens.some(t => t.token === token)) return next();
    logError(`身份验证失败，IP: ${req.ip}`);
    return res.status(401).json({ error: 'Invalid or missing token' });
}

function ckAuth(req, res, next) {
    const sid = req.cookies && req.cookies.adminsid;
    if (sid && adminSes.has(sid)) return next();
    return res.redirect('/admin/login');
}

function apiResponse(success, data = null, message = '') {
    return {
        success,
        data,
        message,
        timestamp: Date.now()
    };
}

const historyPath = path.join(__dirname, 'history.json');
function loadHistory() {
    try {
        const data = fs.readFileSync(historyPath, 'utf-8');
        return JSON.parse(data);
    } catch (err) {
        return [];
    }
}

function saveHistory(history) {
    try {
        fs.writeFileSync(historyPath, JSON.stringify(history, null, 2), 'utf-8');
        return true;
    } catch (err) {
        console.error('保存历史记录失败:', err);
        return false;
    }
}

function addHistory(name, oldValue, newValue, action, ip) {
    const history = loadHistory();
    history.unshift({
        name,
        oldValue,
        newValue,
        action,
        ip,
        timestamp: Date.now()
    });
    // 只保留最近1000条记录
    if (history.length > 1000) history.length = 1000;
    saveHistory(history);
}

// 删除旧的 /get 和 /set 路由，完全使用新的 RESTful API
app.get('/api/v1/variables/:name', ckToken, (req, res) => {
    const name = req.params.name;
    const variable = getSettings().find(v => v.name === name);
    if (!variable) {
        logError(`查询变量失败：${name} 不存在`);
        return res.status(404).json(apiResponse(false, null, 'Variable not found'));
    }
    logInfo(`查询变量：${name}，值：${variable.value}，IP: ${req.ip}`);
    res.json(apiResponse(true, { name: variable.name, value: variable.value }));
});

app.get('/api/v1/variables', ckToken, (req, res) => {
    const variables = getSettings();
    res.json(apiResponse(true, variables));
});

app.get('/api/v1/groups', ckToken, (req, res) => {
    const config = loadConfig();
    res.json(apiResponse(true, config.groups));
});

app.post('/api/v1/groups', ckToken, express.json(), (req, res) => {
    const { name } = req.body;
    if (!name) {
        return res.status(400).json(apiResponse(false, null, 'Missing group name'));
    }
    const config = loadConfig();
    const groupId = crypto.randomBytes(4).toString('hex');
    config.groups.push({ id: groupId, name });
    if (!saveConfig(config)) {
        return res.status(500).json(apiResponse(false, null, 'Save failed'));
    }
    logInfo(`新增分组：${name}，IP: ${req.ip}`);
    res.status(201).json(apiResponse(true, { id: groupId, name }));
});

app.post('/api/v1/variables', ckToken, express.json(), (req, res) => {
    const { name, value, groupId = 'default' } = req.body;
    if (!name || typeof value === 'undefined') {
        logError('新增变量失败：缺少 name 或 value');
        return res.status(400).json(apiResponse(false, null, 'Missing name or value'));
    }
    const config = loadConfig();
    if (config.variables.find(v => v.name === name)) {
        logError(`新增变量失败：${name} 已存在`);
        return res.status(409).json(apiResponse(false, null, 'Variable already exists'));
    }
    if (!config.groups.find(g => g.id === groupId)) {
        return res.status(400).json(apiResponse(false, null, 'Invalid group'));
    }
    config.variables.push({ name, value: String(value), groupId });
    if (!saveConfig(config)) {
        return res.status(500).json(apiResponse(false, null, 'Save failed'));
    }
    // 添加历史记录
    addHistory(name, null, value, 'create', req.ip);
    logInfo(`新增变量：${name}，值：${value}，IP: ${req.ip}`);
    res.status(201).json(apiResponse(true, { name, value }));
});

app.get('/api/v1/variables/:name/history', ckToken, (req, res) => {
    const name = req.params.name;
    const history = loadHistory().filter(h => h.name === name);
    res.json(apiResponse(true, history));
});

app.put('/api/v1/variables/:name', ckToken, express.json(), (req, res) => {
    const name = req.params.name;
    const { value } = req.body;
    if (typeof value === 'undefined') {
        return res.status(400).json(apiResponse(false, null, 'Missing value'));
    }
    const config = loadConfig();
    const variable = config.variables.find(v => v.name === name);
    if (!variable) {
        return res.status(404).json(apiResponse(false, null, 'Variable not found'));
    }
    const oldValue = variable.value;
    variable.value = String(value);
    if (!saveConfig(config)) {
        return res.status(500).json(apiResponse(false, null, 'Save failed'));
    }
    // 添加历史记录
    addHistory(name, oldValue, value, 'update', req.ip);
    logInfo(`修改变量：${name}，原值：${oldValue}，新值：${value}，IP: ${req.ip}`);
    res.json(apiResponse(true, variable));
});

app.delete('/api/v1/variables/:name', ckToken, (req, res) => {
    const name = req.params.name;
    const config = loadConfig();
    const variable = config.variables.find(v => v.name === name);
    if (!variable) {
        return res.status(404).json(apiResponse(false, null, 'Variable not found'));
    }
    const idx = config.variables.findIndex(v => v.name === name);
    config.variables.splice(idx, 1);
    if (!saveConfig(config)) {
        return res.status(500).json(apiResponse(false, null, 'Save failed'));
    }
    // 添加历史记录
    addHistory(name, variable.value, null, 'delete', req.ip);
    logInfo(`删除变量：${name}，IP: ${req.ip}`);
    res.json(apiResponse(true));
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

app.post('/admin/group/delete', ckAuth, express.urlencoded({ extended: false }), (req, res) => {
    const { id } = req.body;
    if (id === 'default') {
        return res.send('默认分组不能删除');
    }
    const config = loadConfig();
    const groupIdx = config.groups.findIndex(g => g.id === id);
    if (groupIdx === -1) return res.send('分组不存在');
    
    // 将该分组下的变量转移到默认分组
    config.variables.forEach(v => {
        if (v.groupId === id) v.groupId = 'default';
    });
    config.groups.splice(groupIdx, 1);
    if (!saveConfig(config)) return res.send('保存失败');
    res.redirect('/admin');
});

app.post('/admin/group/edit', ckAuth, express.urlencoded({ extended: false }), (req, res) => {
    const { id, name } = req.body;
    if (id === 'default' && name !== '默认分组') {
        return res.send('默认分组名称不能修改');
    }
    const config = loadConfig();
    const group = config.groups.find(g => g.id === id);
    if (!group) return res.send('分组不存在');
    group.name = name;
    if (!saveConfig(config)) return res.send('保存失败');
    res.redirect('/admin');
});

app.get('/admin', ckAuth, (req, res) => {
    logInfo(`访问管理面板，IP: ${req.ip}`);
    const config = loadConfig();
    const groups = config.groups;
    const variables = config.variables;
    const search = req.query.search || '';
    const groupId = req.query.group || '';

    // 生成分组选项
    const groupOptions = groups.map(g => 
        `<option value="${g.id}" ${groupId === g.id ? 'selected' : ''}>${g.name}</option>`
    ).join('');

    // 过滤变量
    const filteredVars = variables.filter(v => 
        (!search || v.name.includes(search)) &&
        (!groupId || v.groupId === groupId)
    );

    // 按分组组织变量
    const groupedRows = groups.map(group => {
        const groupVars = filteredVars.filter(v => v.groupId === group.id);
        if (groupVars.length === 0 && groupId && groupId !== group.id) return '';
        
        return `
            <tr class="group-header">
                <td colspan="3" class="table-light">
                    <div class="d-flex justify-content-between align-items-center">
                        <div>
                            <strong>${group.name}</strong>
                            <span class="badge bg-secondary ms-2">${groupVars.length}</span>
                        </div>
                        ${group.id !== 'default' ? `
                            <div class="btn-group btn-group-sm">
                                <button type="button" class="btn btn-outline-primary" 
                                    onclick="editGroup('${group.id}', '${group.name}')">编辑</button>
                                <button type="button" class="btn btn-outline-danger" 
                                    onclick="deleteGroup('${group.id}', '${group.name}')">删除</button>
                            </div>
                        ` : ''}
                    </div>
                </td>
            </tr>
            ${groupVars.map(v => `
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
                        <div class="btn-group btn-group-sm">
                            <a href="/admin/history/${v.name}" class="btn btn-outline-secondary">历史</a>
                            <button type="button" class="btn btn-outline-danger" 
                                onclick="deleteVar('${v.name}')">删除</button>
                        </div>
                    </td>
                </tr>
            `).join('')}
        `;
    }).join('');

    res.send(`
        <html><head><title>ValueAPI - 管理面板</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css">
        <style>
            body { background: #f7f7f7; }
            .sidebar {
                width: 240px;
                position: fixed;
                left: 0;
                top: 0;
                bottom: 0;
                background: #fff;
                border-right: 1px solid #eee;
                padding: 20px 0;
            }
            .main-content {
                margin-left: 240px;
                padding: 20px 30px;
            }
            .sidebar-brand {
                padding: 0 20px 20px;
                border-bottom: 1px solid #eee;
                margin-bottom: 20px;
            }
            .sidebar-nav .nav-link {
                padding: 8px 20px;
                color: #666;
                font-weight: 500;
            }
            .sidebar-nav .nav-link:hover {
                background: #f8f9fa;
                color: #333;
            }
            .sidebar-nav .nav-link.active {
                background: #f0f7ff;
                color: #0d6efd;
            }
            .sidebar-nav .nav-link i {
                margin-right: 8px;
            }
            .top-bar {
                background: #fff;
                border-bottom: 1px solid #eee;
                padding: 15px 0;
                margin: -20px -30px 20px;
            }
            .panel {
                background: #fff;
                border-radius: 8px;
                box-shadow: 0 1px 3px #0001;
            }
            .table > :not(caption) > * > * {
                padding: 1rem;
            }
            .group-header {
                background: #f8f9fa;
            }
            .group-header td {
                padding: 12px 1rem !important;
            }
            .btn-icon {
                padding: 0.375rem;
                line-height: 1;
            }
            .btn-icon i {
                font-size: 1.1rem;
            }
        </style>
        </head><body>
        <div class="sidebar">
            <div class="sidebar-brand">
                <h5 class="mb-0">ValueAPI</h5>
                <small class="text-muted">变量管理系统</small>
            </div>
            <div class="sidebar-nav">
                <a href="/admin" class="nav-link active">
                    <i class="bi bi-gear"></i> 变量管理
                </a>
                <a href="/admin/settings" class="nav-link">
                    <i class="bi bi-sliders"></i> 系统设置
                </a>
            </div>
        </div>

        <div class="main-content">
            <div class="top-bar">
                <div class="container-fluid">
                    <div class="row g-3 align-items-center">
                        <div class="col-auto">
                            <div class="input-group">
                                <span class="input-group-text bg-white">
                                    <i class="bi bi-search text-muted"></i>
                                </span>
                                <input type="text" class="form-control border-start-0" id="searchInput" 
                                    placeholder="搜索变量" value="${search}">
                            </div>
                        </div>
                        <div class="col-auto">
                            <select class="form-select" id="groupFilter">
                                <option value="">所有分组</option>
                                ${groupOptions}
                            </select>
                        </div>
                        <div class="col-auto ms-auto">
                            <button type="button" class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#addGroupModal">
                                <i class="bi bi-plus-lg me-1"></i>新增分组
                            </button>
                        </div>
                    </div>
                </div>
            </div>

            <div class="panel">
                <table class="table table-bordered align-middle mb-0">
                    <thead class="bg-light">
                        <tr>
                            <th style="width:30%">变量名</th>
                            <th>值</th>
                            <th style="width:180px" class="text-end">操作</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${groups.map(group => {
                            const groupVars = filteredVars.filter(v => v.groupId === group.id);
                            if (groupVars.length === 0 && groupId && groupId !== group.id) return '';
                            
                            return `
                                <tr class="group-header">
                                    <td colspan="3">
                                        <div class="d-flex justify-content-between align-items-center">
                                            <div>
                                                <strong>${group.name}</strong>
                                                <span class="badge bg-secondary bg-opacity-75 ms-2">${groupVars.length}</span>
                                            </div>
                                            ${group.id !== 'default' ? `
                                                <div class="btn-group btn-group-sm">
                                                    <button type="button" class="btn btn-icon btn-outline-secondary" 
                                                        onclick="editGroup('${group.id}', '${group.name}')" title="编辑分组">
                                                        <i class="bi bi-pencil"></i>
                                                    </button>
                                                    <button type="button" class="btn btn-icon btn-outline-danger" 
                                                        onclick="deleteGroup('${group.id}', '${group.name}')" title="删除分组">
                                                        <i class="bi bi-trash"></i>
                                                    </button>
                                                </div>
                                            ` : ''}
                                        </div>
                                    </td>
                                </tr>
                                ${groupVars.map(v => `
                                    <tr>
                                        <td class="text-break">${v.name}</td>
                                        <td>
                                            <form method="POST" action="/admin/edit" class="d-flex align-items-center">
                                                <input type="hidden" name="name" value="${v.name}">
                                                <input name="value" value="${v.value}" class="form-control form-control-sm me-2">
                                                <button type="submit" class="btn btn-sm btn-primary px-3">保存</button>
                                            </form>
                                        </td>
                                        <td class="text-end">
                                            <div class="btn-group btn-group-sm">
                                                <a href="/admin/history/${v.name}" class="btn btn-icon btn-outline-secondary" title="历史记录">
                                                    <i class="bi bi-clock-history"></i>
                                                </a>
                                                <button type="button" class="btn btn-icon btn-outline-danger" 
                                                    onclick="deleteVar('${v.name}')" title="删除">
                                                    <i class="bi bi-trash"></i>
                                                </button>
                                            </div>
                                        </td>
                                    </tr>
                                `).join('')}
                            `;
                        }).join('')}
                    </tbody>
                </table>
            </div>

            <div class="mt-4">
                <div class="panel p-4">
                    <h5 class="mb-3">添加变量</h5>
                    <form method="POST" action="/admin/add" class="row g-3">
                        <div class="col-4">
                            <label class="form-label">变量名</label>
                            <input name="name" class="form-control" required>
                        </div>
                        <div class="col-4">
                            <label class="form-label">值</label>
                            <input name="value" class="form-control" required>
                        </div>
                        <div class="col-2">
                            <label class="form-label">分组</label>
                            <select name="groupId" class="form-select">
                                ${groupOptions}
                            </select>
                        </div>
                        <div class="col-2">
                            <label class="form-label">&nbsp;</label>
                            <button type="submit" class="btn btn-primary w-100">添加</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>

        <!-- 新增分组模态框 -->
        <div class="modal fade" id="addGroupModal">
            <div class="modal-dialog">
                <div class="modal-content">
                    <form method="POST" action="/admin/group/add">
                        <div class="modal-header">
                            <h5 class="modal-title">新增分组</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                        </div>
                        <div class="modal-body">
                            <input name="name" class="form-control" placeholder="分组名称" required />
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">取消</button>
                            <button type="submit" class="btn btn-primary">确定</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>

        <!-- 编辑分组模态框 -->
        <div class="modal fade" id="editGroupModal" tabindex="-1">
            <div class="modal-dialog">
                <div class="modal-content">
                    <form method="POST" action="/admin/group/edit">
                        <input type="hidden" name="id" id="editGroupId">
                        <div class="modal-header">
                            <h5 class="modal-title">编辑分组</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                        </div>
                        <div class="modal-body">
                            <input name="name" id="editGroupName" class="form-control" placeholder="分组名称" required />
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">取消</button>
                            <button type="submit" class="btn btn-primary">保存</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>

        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
        <script>
            let editModal;
            window.onload = () => {
                editModal = new bootstrap.Modal(document.getElementById('editGroupModal'));
            };

            function updateSearch() {
                const search = document.getElementById('searchInput').value.trim();
                const group = document.getElementById('groupFilter').value;
                const params = new URLSearchParams(window.location.search);
                if (search) params.set('search', search);
                else params.delete('search');
                if (group) params.set('group', group);
                else params.delete('group');
                window.location.search = params.toString();
            }

            // 添加搜索延迟
            let searchTimeout;
            document.getElementById('searchInput').addEventListener('input', () => {
                clearTimeout(searchTimeout);
                searchTimeout = setTimeout(updateSearch, 300);
            });

            document.getElementById('groupFilter').addEventListener('change', updateSearch);

            function editGroup(id, name) {
                document.getElementById('editGroupId').value = id;
                document.getElementById('editGroupName').value = name;
                editModal.show();
            }

            function deleteGroup(id, name) {
                if (!confirm(\`确定要删除分组【\${name}】吗？该分组下的变量将被移动到默认分组。\`)) return;
                const form = document.createElement('form');
                form.method = 'POST';
                form.action = '/admin/group/delete';
                const input = document.createElement('input');
                input.name = 'id';
                input.value = id;
                form.appendChild(input);
                document.body.appendChild(form);
                form.submit();
            }

            function deleteVar(name) {
                if (!confirm(\`确定要删除变量【\${name}】吗？\`)) return;
                const form = document.createElement('form');
                form.method = 'POST';
                form.action = '/admin/delete';
                const input = document.createElement('input');
                input.name = 'name';
                input.value = name;
                form.appendChild(input);
                document.body.appendChild(form);
                form.submit();
            }
        </script>
        </body></html>
    `);
});

app.get('/admin/history/:name', ckAuth, (req, res) => {
    const name = req.params.name;
    const history = loadHistory().filter(h => h.name === name);
    const variable = getSettings().find(v => v.name === name);
    if (!variable) return res.redirect('/admin');

    const rows = history.map(h => {
        const time = new Date(h.timestamp).toLocaleString();
        const actionMap = { create: '创建', update: '修改', delete: '删除' };
        const actionClass = {
            create: 'bg-success',
            update: 'bg-primary',
            delete: 'bg-danger'
        };
        return `
            <tr>
                <td class="text-nowrap">${time}</td>
                <td><span class="badge ${actionClass[h.action]} bg-opacity-75">${actionMap[h.action] || h.action}</span></td>
                <td><code>${h.oldValue === null ? '-' : h.oldValue}</code></td>
                <td><code>${h.newValue === null ? '-' : h.newValue}</code></td>
                <td class="text-nowrap">${h.ip}</td>
                <td class="text-end">
                    ${h.action === 'update' ? `
                        <button type="button" class="btn btn-sm btn-outline-primary"
                            onclick="rollback('${name}', '${h.oldValue}')">恢复此版本</button>
                    ` : ''}
                </td>
            </tr>
        `;
    }).join('');

    res.send(`
        <html><head><title>变量历史 - ValueAPI</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>
            body { background: #f7f7f7; }
            .panel { background: #fff; padding: 24px; border-radius: 8px; box-shadow: 0 2px 8px #0001; max-width: 1000px; margin: 40px auto; }
            code { background: #f5f5f5; padding: 2px 6px; border-radius: 4px; }
        </style>
        </head><body>
        <div class="panel">
            <div class="d-flex justify-content-between align-items-center mb-4">
                <div>
                    <h4 class="m-0">变量历史记录</h4>
                    <div class="text-muted mt-1">
                        <strong>${name}</strong> 
                        <span class="mx-2">•</span>
                        当前值：<code>${variable.value}</code>
                    </div>
                </div>
                <a href="/admin" class="btn btn-outline-secondary">返回</a>
            </div>
            <table class="table table-bordered align-middle">
                <thead class="table-light">
                    <tr>
                        <th>时间</th>
                        <th>操作</th>
                        <th>原值</th>
                        <th>新值</th>
                        <th>IP</th>
                        <th></th>
                    </tr>
                </thead>
                <tbody>${rows}</tbody>
            </table>
            ${history.length === 0 ? '<div class="text-center text-muted py-4">暂无历史记录</div>' : ''}
        </div>

        <script>
        function rollback(name, value) {
            if (!confirm('确定要恢复到这个版本吗？')) return;
            const form = document.createElement('form');
            form.method = 'POST';
            form.action = '/admin/edit';
            const nameInput = document.createElement('input');
            nameInput.name = 'name';
            nameInput.value = name;
            const valueInput = document.createElement('input');
            valueInput.name = 'value';
            valueInput.value = value;
            form.appendChild(nameInput);
            form.appendChild(valueInput);
            document.body.appendChild(form);
            form.submit();
        }
        </script>
        </body></html>
    `);
});

// 更新首页文档
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
                <h5>REST API 接口说明</h5>
                <p class="text-muted small">所有请求需要在URL参数中携带 token</p>
                <ul>
                    <li><b>查询所有变量：</b> <code>GET /api/v1/variables</code></li>
                    <li><b>查询单个变量：</b> <code>GET /api/v1/variables/:name</code></li>
                    <li><b>新增变量：</b> <code>POST /api/v1/variables</code></li>
                    <li><b>修改变量：</b> <code>PUT /api/v1/variables/:name</code></li>
                    <li><b>删除变量：</b> <code>DELETE /api/v1/variables/:name</code></li>
                </ul>
                <h6 class="mt-4">请求示例</h6>
                <div class="mb-2">
                    <p class="mb-1 small text-muted">查询变量</p>
                    <pre class="bg-light p-2 rounded"><code>curl "http://localhost:${PORT}/api/v1/variables/foo?token=你的Token"</code></pre>
                </div>
                <div class="mb-2">
                    <p class="mb-1 small text-muted">添加变量</p>
                    <pre class="bg-light p-2 rounded"><code>curl -X POST "http://localhost:${PORT}/api/v1/variables?token=你的Token" \\
    -H "Content-Type: application/json" \\
    -d '{"name":"foo","value":"bar"}'</code></pre>
                </div>
                <div class="mb-2">
                    <p class="mb-1 small text-muted">修改变量</p>
                    <pre class="bg-light p-2 rounded"><code>curl -X PUT "http://localhost:${PORT}/api/v1/variables/foo?token=你的Token" \\
    -H "Content-Type: application/json" \\
    -d '{"value":"newbar"}'</code></pre>
                </div>
                <div class="mb-2">
                    <p class="mb-1 small text-muted">删除变量</p>
                    <pre class="bg-light p-2 rounded"><code>curl -X DELETE "http://localhost:${PORT}/api/v1/variables/foo?token=你的Token"</code></pre>
                </div>
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
    console.log(`|------------------Version: ${version}------------------------|`);
    console.log(`|----------------------------------------------------------|`);
    logInfo(`ValueAPI运行在 http://localhost:${PORT}${version}`);
});

// 在 const TOKEN = process.env.TOKEN; 后添加系统设置相关代码
const systemSettingsPath = path.join(__dirname, 'settings.json');

function loadSystemSettings() {
    try {
        const data = fs.readFileSync(systemSettingsPath, 'utf-8');
        const settings = JSON.parse(data);
        // 确保默认令牌存在
        const defaultToken = settings.tokens.find(t => t.name === 'Default');
        if (!defaultToken) {
            settings.tokens.unshift({ 
                name: 'Default', 
                token: TOKEN, 
                remark: '默认令牌',
                createdAt: Date.now(),
                isDefault: true
            });
        } else {
            // 不更新默认令牌的值，保持用户设置的值
            defaultToken.isDefault = true;
        }
        return settings;
    } catch (err) {
        const defaultSettings = {
            tokens: [{
                name: 'Default',
                token: TOKEN,
                remark: '默认令牌',
                createdAt: Date.now(),
                isDefault: true
            }],
            settings: {
                historyLimit: 1000,
                pageSize: 50,
                allowNewToken: true
            }
        };
        fs.writeFileSync(systemSettingsPath, JSON.stringify(defaultSettings, null, 2));
        return defaultSettings;
    }
}

function saveSystemSettings(settings) {
    try {
        fs.writeFileSync(systemSettingsPath, JSON.stringify(settings, null, 2), 'utf-8');
        return true;
    } catch (err) {
        console.error('保存系统设置失败:', err);
        return false;
    }
}

// 修改 ckToken 中间件支持多令牌验证
function ckToken(req, res, next) {
    const token = req.query.token;
    const settings = loadSystemSettings();
    if (settings.tokens.some(t => t.token === token)) return next();
    logError(`身份验证失败，IP: ${req.ip}`);
    return res.status(401).json({ error: 'Invalid or missing token' });
}

// 修改令牌管理API路由
app.post('/admin/settings/token/add', ckAuth, express.json(), (req, res) => {
    const { name, remark } = req.body;
    if (!name) return res.json({ error: '请输入令牌名称' });
    
    const settings = loadSystemSettings();
    if (settings.tokens.find(t => t.name === name)) {
        return res.json({ error: '令牌名称已存在' });
    }
    
    const token = crypto.randomBytes(16).toString('hex');
    settings.tokens.push({ 
        name, 
        token,
        remark: remark || '',
        createdAt: Date.now()
    });
    
    if (!saveSystemSettings(settings)) {
        return res.json({ error: '保存失败' });
    }
    
    res.json({ 
        success: true, 
        token,
        message: '创建成功！新令牌：' + token 
    });
});

app.post('/admin/settings/token/delete', ckAuth, express.json(), (req, res) => {
    const { name } = req.body;
    if (name === 'Default') {
        return res.json({ error: '默认令牌不能删除' });
    }
    
    const settings = loadSystemSettings();
    const idx = settings.tokens.findIndex(t => t.name === name);
    if (idx === -1) {
        return res.json({ error: '令牌不存在' });
    }
    
    settings.tokens.splice(idx, 1);
    if (!saveSystemSettings(settings)) {
        return res.json({ error: '保存失败' });
    }
    
    res.json({ success: true, message: '删除成功' });
});

// 修改系统设置页面中的令牌管理部分
app.get('/admin/settings', ckAuth, (req, res) => {
    const settings = loadSystemSettings();
    res.send(`
        <html><head><title>系统设置 - ValueAPI</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css">
        <style>
            body { background: #f7f7f7; }
            .sidebar {
                width: 240px;
                position: fixed;
                left: 0;
                top: 0;
                bottom: 0;
                background: #fff;
                border-right: 1px solid #eee;
                padding: 20px 0;
            }
            .main-content {
                margin-left: 240px;
                padding: 20px 30px;
            }
            .sidebar-brand {
                padding: 0 20px 20px;
                border-bottom: 1px solid #eee;
                margin-bottom: 20px;
            }
            .sidebar-nav .nav-link {
                padding: 8px 20px;
                color: #666;
                font-weight: 500;
            }
            .sidebar-nav .nav-link:hover {
                background: #f8f9fa;
                color: #333;
            }
            .sidebar-nav .nav-link.active {
                background: #f0f7ff;
                color: #0d6efd;
            }
            .sidebar-nav .nav-link i {
                margin-right: 8px;
            }
            .top-bar {
                background: #fff;
                border-bottom: 1px solid #eee;
                padding: 15px 0;
                margin: -20px -30px 20px;
            }
            .panel {
                background: #fff;
                border-radius: 8px;
                box-shadow: 0 1px 3px #0001;
            }
            .table > :not(caption) > * > * {
                padding: 1rem;
            }
            .group-header {
                background: #f8f9fa;
            }
            .group-header td {
                padding: 12px 1rem !important;
            }
            .btn-icon {
                padding: 0.375rem;
                line-height: 1;
            }
            .btn-icon i {
                font-size: 1.1rem;
            }
        </style>
        </head><body>
        <div class="sidebar">
            <div class="sidebar-brand">
                <h5 class="mb-0">ValueAPI</h5>
                <small class="text-muted">变量管理系统</small>
            </div>
            <div class="sidebar-nav">
                <a href="/admin" class="nav-link">
                    <i class="bi bi-gear"></i> 变量管理
                </a>
                <a href="/admin/settings" class="nav-link active">
                    <i class="bi bi-sliders"></i> 系统设置
                </a>
            </div>
        </div>

        <div class="main-content">
            <div class="row g-4">
                <div class="col-12">
                    <div class="panel p-4">
                        <div class="d-flex justify-content-between align-items-center mb-3">
                            <h5 class="m-0">访问令牌管理</h5>
                            <button type="button" class="btn btn-primary" onclick="showNewToken()">
                                <i class="bi bi-plus-lg"></i> 新建令牌
                            </button>
                        </div>
                        <div class="table-responsive">
                            <table class="table table-bordered align-middle mb-0">
                                <thead class="table-light">
                                    <tr>
                                        <th>名称</th>
                                        <th width="280">令牌</th>
                                        <th>备注</th>
                                        <th>创建时间</th>
                                        <th width="100">操作</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${settings.tokens.map(t => `
                                        <tr>
                                            <td>${t.name}</td>
                                            <td>
                                                <div class="d-flex align-items-center">
                                                    <input type="text" class="form-control form-control-sm" 
                                                        value="${t.token}" 
                                                        ${t.isDefault ? '' : 'readonly'}
                                                        style="font-family: monospace;"
                                                        id="token-${t.name}">
                                                    <button class="btn btn-sm btn-link ms-2" 
                                                        onclick="copyToken('${t.name}')">
                                                        <i class="bi bi-clipboard"></i>
                                                    </button>
                                                    ${t.isDefault ? `
                                                        <button class="btn btn-sm btn-primary ms-1" 
                                                            onclick="saveToken('${t.name}')">
                                                            <i class="bi bi-check"></i>
                                                        </button>
                                                    ` : ''}
                                                </div>
                                            </td>
                                            <td>
                                                <input type="text" class="form-control form-control-sm" 
                                                    value="${t.remark || ''}" 
                                                    onchange="updateRemark('${t.name}', this.value)"
                                                    placeholder="点击添加备注">
                                            </td>
                                            <td>${t.createdAt ? new Date(t.createdAt).toLocaleString() : '-'}</td>
                                            <td class="text-center">
                                                ${t.isDefault ? '-' : `
                                                    <button class="btn btn-sm btn-outline-danger" 
                                                        onclick="deleteToken('${t.name}')">
                                                        <i class="bi bi-trash"></i>
                                                    </button>
                                                `}
                                            </td>
                                        </tr>
                                    `).join('')}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
                
                <div class="col-12">
                    <div class="panel p-4">
                        <h5 class="mb-3">系统参数设置</h5>
                        <form method="POST" action="/admin/settings/save" class="row g-3">
                            <div class="col-md-6">
                                <label class="form-label">历史记录限制</label>
                                <input type="number" name="historyLimit" class="form-control" 
                                    value="${settings.settings.historyLimit}">
                                <div class="form-text">历史记录保留的最大条数</div>
                            </div>
                            <div class="col-md-6">
                                <label class="form-label">每页显示数量</label>
                                <input type="number" name="pageSize" class="form-control" 
                                    value="${settings.settings.pageSize}">
                                <div class="form-text">变量列表每页显示的数量</div>
                            </div>
                            <div class="col-12">
                                <div class="form-check form-switch">
                                    <input class="form-check-input" type="checkbox" name="allowNewToken" 
                                        ${settings.settings.allowNewToken ? 'checked' : ''}>
                                    <label class="form-check-label">允许创建新令牌</label>
                                </div>
                            </div>
                            <div class="col-12">
                                <button type="submit" class="btn btn-primary">保存设置</button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>

        <!-- 新增令牌模态框 -->
        <div class="modal fade" id="newTokenModal">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">新建访问令牌</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <div class="mb-3">
                            <label class="form-label required">令牌名称</label>
                            <input type="text" class="form-control" id="tokenName" required>
                            <div class="form-text">用于标识令牌用途</div>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">备注说明</label>
                            <input type="text" class="form-control" id="tokenRemark">
                            <div class="form-text">可选的补充说明</div>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">取消</button>
                        <button type="button" class="btn btn-primary" onclick="createToken()">创建</button>
                    </div>
                </div>
            </div>
        </div>

        <script>
        const tokenModal = new bootstrap.Modal(document.getElementById('newTokenModal'));
        
        function showNewToken() {
            document.getElementById('tokenName').value = '';
            document.getElementById('tokenRemark').value = '';
            tokenModal.show();
        }
        
        async function createToken() {
            const name = document.getElementById('tokenName').value.trim();
            const remark = document.getElementById('tokenRemark').value.trim();
            
            if (!name) {
                alert('请输入令牌名称');
                return;
            }
            
            try {
                const res = await fetch('/admin/settings/token/add', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ name, remark })
                });
                
                const data = await res.json();
                if (data.error) {
                    alert(data.error);
                    return;
                }
                
                alert(data.message || '创建成功');
                location.reload();
            } catch (err) {
                alert('创建失败：' + err.message);
            }
        }
        
        async function deleteToken(name) {
            if (!confirm('确定要删除此令牌吗？删除后使用此令牌的应用将无法访问。')) return;
            
            try {
                const res = await fetch('/admin/settings/token/delete', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ name })
                });
                
                const data = await res.json();
                if (data.error) {
                    alert(data.error);
                    return;
                }
                
                alert(data.message || '删除成功');
                location.reload();
            } catch (err) {
                alert('删除失败：' + err.message);
            }
        }

        function copyToken(name) {
            const input = document.getElementById('token-' + name);
            input.select();
            document.execCommand('copy');
            alert('令牌已复制到剪贴板');
        }

        async function saveToken(name) {
            const token = document.getElementById('token-' + name).value.trim();
            if (!token) {
                alert('令牌不能为空');
                return;
            }
            
            try {
                const res = await fetch('/admin/settings/token/edit', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ name, token })
                });
                
                const data = await res.json();
                if (data.error) {
                    alert(data.error);
                    return;
                }
                
                alert('保存成功');
            } catch (err) {
                alert('保存失败：' + err.message);
            }
        }

        async function updateRemark(name, remark) {
            try {
                const res = await fetch('/admin/settings/token/edit', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ name, remark })
                });
                
                const data = await res.json();
                if (data.error) {
                    alert(data.error);
                    return;
                }
            } catch (err) {
                alert('更新失败：' + err.message);
            }
        }
        </script>
        </body></html>
    `);
});

// 添加设置相关路由
app.post('/admin/settings/save', ckAuth, express.urlencoded({ extended: false }), (req, res) => {
    const { historyLimit, pageSize, allowNewToken } = req.body;
    const settings = loadSystemSettings();
    settings.settings = {
        historyLimit: parseInt(historyLimit) || 1000,
        pageSize: parseInt(pageSize) || 50,
        allowNewToken: allowNewToken === 'on'
    };
    if (saveSystemSettings(settings)) {
        res.redirect('/admin/settings');
    } else {
        res.send('保存失败');
    }
});

app.post('/admin/settings/token/add', ckAuth, express.urlencoded({ extended: false }), (req, res) => {
    const { name } = req.body;
    const settings = loadSystemSettings();
    if (!settings.settings.allowNewToken) {
        return res.send('系统不允许创建新令牌');
    }
    if (settings.tokens.find(t => t.name === name)) {
        return res.send('令牌名称已存在');
    }
    const token = crypto.randomBytes(16).toString('hex');
    settings.tokens.push({ name, token });
    if (saveSystemSettings(settings)) {
        res.redirect('/admin/settings');
    } else {
        res.send('保存失败');
    }
});

app.post('/admin/settings/token/delete', ckAuth, express.urlencoded({ extended: false }), (req, res) => {
    const { name } = req.body;
    const settings = loadSystemSettings();
    const idx = settings.tokens.findIndex(t => t.name === name);
    if (idx === -1 || name === 'Default') {
        return res.send('无法删除此令牌');
    }
    settings.tokens.splice(idx, 1);
    if (saveSystemSettings(settings)) {
        res.redirect('/admin/settings');
    } else {
        res.send('删除失败');
    }
});

// 添加令牌编辑接口
app.post('/admin/settings/token/edit', ckAuth, express.json(), (req, res) => {
    const { name, token, remark } = req.body;
    const settings = loadSystemSettings();
    
    const targetToken = settings.tokens.find(t => t.name === name);
    if (!targetToken) {
        return res.json({ error: '令牌不存在' });
    }
    
    if (token) targetToken.token = token;
    if (typeof remark !== 'undefined') targetToken.remark = remark;
    
    if (!saveSystemSettings(settings)) {
        return res.json({ error: '保存失败' });
    }
    
    res.json({ success: true });
});
