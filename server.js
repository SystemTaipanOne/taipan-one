require('dotenv').config();

const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');
const crypto = require('crypto'); // Adicionado para gerar chaves únicas

const app = express();
app.use(cors());
app.use(express.json());

app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization");
  res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  next();
});

app.use(express.static(path.join(__dirname, 'public')));

const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

pool.getConnection()
    .then(conn => {
        console.log('Connected to MySQL database');
        conn.release();
    })
    .catch(err => {
        console.error('Failed to connect to MySQL:', err.message);
        process.exit(1);
    });

const JWT_SECRET = process.env.JWT_SECRET;

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Token não fornecido' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Token inválido' });
        req.user = user;
        next();
    });
}

function ensureSuperAdmin(req, res, next) {
    if (req.user.role_id !== 1) { // Alterado de 101 para 1, conforme a tabela roles
        return res.status(403).json({ message: 'Acesso restrito a super admins' });
    }
    next();
}

function ensureMasterAdmin(req, res, next) {
    if (req.user.role_id !== 1 || !req.user.canManageSuperAdmins) {
        return res.status(403).json({ message: 'Acesso restrito ao admin master.' });
    }
    next();
}

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const [rows] = await pool.query('SELECT *, can_manage_super_admins FROM users WHERE username = ?', [username]);
        const user = rows[0];
        if (!user) return res.status(401).json({ message: 'Credenciais inválidas' });

        const match = await bcrypt.compare(password, user.password_hash);
        if (!match) return res.status(401).json({ message: 'Credenciais inválidas' });

        const tokenPayload = { 
            id: user.id, 
            role_id: user.role_id,
            canManageSuperAdmins: !!user.can_manage_super_admins 
        };
        const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: '1h' });
        
        res.json({
            accessToken: token,
            user: {
                id: user.id,
                fullName: user.full_name,
                role: { name: user.role_id === 1 ? 'Super Admin' : 'Other' },
                canManageSuperAdmins: !!user.can_manage_super_admins,
                permissions: user.role_id === 1 ? [
                    { id: 'admin_dashboard', name: 'Dashboard Admin' },
                    { id: 'admin_client_management', name: 'Gestão de Clientes' },
                    { id: 'admin_activations', name: 'Chaves de Ativação' } // Adicionado
                ] : []
            }
        });
    } catch (error) {
        console.error('Erro no login:', error.message);
        res.status(500).json({ message: 'Erro no servidor' });
    }
});

app.get('/api/admin/superadmins', authenticateToken, ensureMasterAdmin, async (req, res) => {
    try {
        const [rows] = await pool.query("SELECT id, username, full_name, can_manage_super_admins FROM users WHERE role_id = 1 ORDER BY id");
        res.json(rows);
    } catch(error) {
        res.status(500).json({ message: 'Erro ao buscar administradores.' });
    }
});

app.post('/api/admin/superadmins', authenticateToken, ensureMasterAdmin, async (req, res) => {
    const { username, fullName, password, canManage } = req.body;
    if (!username || !fullName || !password) {
        return res.status(400).json({ message: "Todos os campos são obrigatórios." });
    }
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query(
            "INSERT INTO users (username, full_name, password_hash, role_id, can_manage_super_admins, email, is_active) VALUES (?, ?, ?, 1, ?, ?, 1)",
            [username, fullName, hashedPassword, canManage ? 1 : 0, `${username}@taipan.local`]
        );
        res.status(201).json({ message: "Super Admin criado com sucesso." });
    } catch(error) {
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ message: "Username já existe." });
        }
        res.status(500).json({ message: 'Erro ao criar Super Admin.' });
    }
});

app.delete('/api/admin/superadmins/:id', authenticateToken, ensureMasterAdmin, async (req, res) => {
    const adminIdToDelete = parseInt(req.params.id, 10);
    
    if (adminIdToDelete === req.user.id) {
        return res.status(403).json({ message: "Não pode excluir a si mesmo." });
    }

    const [[userToDelete]] = await pool.query("SELECT can_manage_super_admins, username FROM users WHERE id = ?", [adminIdToDelete]);
    if (userToDelete && userToDelete.username === 'master') {
         return res.status(403).json({ message: "O administrador master não pode ser excluído." });
    }

    try {
        const [result] = await pool.query("DELETE FROM users WHERE id = ? AND role_id = 1", [adminIdToDelete]);
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: "Administrador não encontrado." });
        }
        res.json({ message: "Super Admin excluído com sucesso." });
    } catch(error) {
        res.status(500).json({ message: 'Erro ao excluir Super Admin.' });
    }
});

app.get('/api/admin/clients', authenticateToken, ensureSuperAdmin, async (req, res) => {
    try {
        const [rows] = await pool.query(`
            SELECT c.id, c.name, GROUP_CONCAT(m.name) AS licensed_modules
            FROM companies c
            LEFT JOIN company_module_access cm ON c.id = cm.company_id
            LEFT JOIN modules m ON cm.module_id = m.id
            GROUP BY c.id, c.name
        `);
        res.json(rows);
    } catch (error) {
        console.error('Erro ao listar clientes:', error.message);
        res.status(500).json({ message: 'Erro ao buscar clientes' });
    }
});

app.get('/api/admin/clients/:id', authenticateToken, ensureSuperAdmin, async (req, res) => {
    try {
        const [rows] = await pool.query(`
            SELECT c.id, c.name, c.niche, GROUP_CONCAT(m.name) AS licensed_modules 
            FROM companies c 
            LEFT JOIN company_module_access cm ON c.id = cm.company_id 
            LEFT JOIN modules m ON cm.module_id = m.id 
            WHERE c.id = ? 
            GROUP BY c.id, c.name, c.niche
        `, [req.params.id]);
        if (!rows[0]) return res.status(404).json({ message: 'Cliente não encontrado' });
        res.json(rows[0]);
    } catch (error) {
        console.error('Erro ao obter cliente:', error.message);
        res.status(500).json({ message: 'Erro no servidor' });
    }
});

app.get('/api/admin/clients/:id/users', authenticateToken, ensureSuperAdmin, async (req, res) => {
    try {
        const [rows] = await pool.query(`
            SELECT u.id, u.username, u.full_name, u.is_active
            FROM users u
            WHERE u.company_id = ? AND u.role_id != 1
        `, [req.params.id]);
        res.json(rows);
    } catch (error) {
        console.error('Erro ao listar usuários:', error.message);
        res.status(500).json({ message: 'Erro ao buscar usuários' });
    }
});

app.post('/api/admin/companies', authenticateToken, ensureSuperAdmin, async (req, res) => {
    const { companyName, niche, adminUsername, adminPassword, adminFullName, modules } = req.body;
    try {
        await pool.query('BEGIN');
        const [companyResult] = await pool.query('INSERT INTO companies (name, niche) VALUES (?, ?)', [companyName, niche]);
        const companyId = companyResult.insertId;

        const hashedPassword = await bcrypt.hash(adminPassword, 10);
        const [adminUserResult] = await pool.query('INSERT INTO users (username, password_hash, full_name, company_id, role_id, is_active, email) VALUES (?, ?, ?, ?, ?, ?, ?)', 
            [adminUsername, hashedPassword, adminFullName, companyId, 2, 1, `${adminUsername}@company.local`]);
        const adminUserId = adminUserResult.insertId;

        if (modules && modules.length > 0) {
            for (const moduleName of modules) {
                const [[module]] = await pool.query('SELECT id FROM modules WHERE name = ?', [moduleName]);
                if (module) {
                    await pool.query('INSERT INTO company_module_access (company_id, module_id) VALUES (?, ?)', [companyId, module.id]);
                }
            }
        }

        await pool.query('COMMIT');
        res.status(201).json({ message: 'Empresa criada com sucesso' });
    } catch (error) {
        console.error('Erro ao criar empresa:', error.message);
        await pool.query('ROLLBACK');
        res.status(500).json({ message: 'Falha ao criar empresa' });
    }
});

app.put('/api/admin/clients/:id', authenticateToken, ensureSuperAdmin, async (req, res) => {
    const { companyName } = req.body;
    try {
        await pool.query('UPDATE companies SET name = ? WHERE id = ?', [companyName, req.params.id]);
        res.json({ message: 'Cliente atualizado com sucesso' });
    } catch (error) {
        console.error('Erro ao atualizar cliente:', error.message);
        res.status(500).json({ message: 'Falha ao atualizar cliente' });
    }
});

app.put('/api/admin/clients/:id/modules', authenticateToken, ensureSuperAdmin, async (req, res) => {
    const { niche, modules } = req.body;
    const companyId = req.params.id;
    try {
        await pool.query('BEGIN');
        await pool.query('UPDATE companies SET niche = ? WHERE id = ?', [niche, companyId]);
        await pool.query('DELETE FROM company_module_access WHERE company_id = ?', [companyId]);
        if (modules && modules.length > 0) {
            for (const moduleName of modules) {
                const [[module]] = await pool.query('SELECT id FROM modules WHERE name = ?', [moduleName]);
                if (module) {
                    await pool.query('INSERT INTO company_module_access (company_id, module_id) VALUES (?, ?)', [companyId, module.id]);
                }
            }
        }
        await pool.query('COMMIT');
        res.json({ message: 'Módulos atualizados com sucesso' });
    } catch (error) {
        console.error('Erro ao atualizar módulos:', error.message);
        await pool.query('ROLLBACK');
        res.status(500).json({ message: 'Falha ao atualizar módulos' });
    }
});

app.delete('/api/admin/clients/:id', authenticateToken, ensureSuperAdmin, async (req, res) => {
    try {
        await pool.query('BEGIN');
        const [users] = await pool.query("SELECT id FROM users WHERE company_id = ?", [req.params.id]);
        if (users.length > 0) {
            const userIds = users.map(u => u.id);
            await pool.query("DELETE FROM user_module_access WHERE user_id IN (?)", [userIds]);
        }
        await pool.query('DELETE FROM company_module_access WHERE company_id = ?', [req.params.id]);
        await pool.query('DELETE FROM users WHERE company_id = ?', [req.params.id]);
        await pool.query('DELETE FROM companies WHERE id = ?', [req.params.id]);
        await pool.query('COMMIT');
        res.json({ message: 'Cliente e todos os dados associados foram deletados com sucesso' });
    } catch (error) {
        console.error('Erro ao deletar cliente:', error.message);
        await pool.query('ROLLBACK');
        res.status(500).json({ message: 'Falha ao deletar cliente' });
    }
});

// Novas rotas para chaves de ativação
app.get('/api/admin/modules', authenticateToken, ensureSuperAdmin, async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT id, name FROM modules');
        res.json(rows);
    } catch (error) {
        console.error('Erro ao listar módulos:', error.message);
        res.status(500).json({ message: 'Erro ao buscar módulos' });
    }
});

app.get('/api/admin/keys', authenticateToken, ensureSuperAdmin, async (req, res) => {
    try {
        const [rows] = await pool.query(`
            SELECT k.id, k.chave, c.name AS company_name, k.modulos, k.valid_until, k.usada
            FROM chaves_ativacao k
            JOIN companies c ON k.empresa_id = c.id
        `);
        res.json(rows);
    } catch (error) {
        console.error('Erro ao listar chaves:', error.message);
        res.status(500).json({ message: 'Erro ao buscar chaves' });
    }
});

app.post('/api/admin/keys', authenticateToken, ensureSuperAdmin, async (req, res) => {
    const { companyId, validityDays, modules } = req.body;
    if (!companyId || !validityDays) {
        return res.status(400).json({ message: 'Empresa e validade são obrigatórios.' });
    }
    try {
        const chave = crypto.randomBytes(16).toString('hex');
        const validUntil = new Date();
        validUntil.setDate(validUntil.getDate() + parseInt(validityDays));
        await pool.query(
            'INSERT INTO chaves_ativacao (chave, empresa_id, valid_until, modulos, usada) VALUES (?, ?, ?, ?, ?)',
            [chave, companyId, validUntil, modules.join(','), false]
        );
        res.status(201).json({ message: 'Chave criada com sucesso', chave });
    } catch (error) {
        console.error('Erro ao criar chave:', error.message);
        res.status(500).json({ message: 'Erro ao criar chave' });
    }
});

app.delete('/api/admin/keys/:id', authenticateToken, ensureSuperAdmin, async (req, res) => {
    try {
        const [result] = await pool.query('DELETE FROM chaves_ativacao WHERE id = ?', [req.params.id]);
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Chave não encontrada' });
        }
        res.json({ message: 'Chave excluída com sucesso' });
    } catch (error) {
        console.error('Erro ao excluir chave:', error.message);
        res.status(500).json({ message: 'Erro ao excluir chave' });
    }
});

app.post('/api/ativar_cliente', async (req, res) => {
    const { chave } = req.body;
    try {
        const [rows] = await pool.query(
            'SELECT * FROM chaves_ativacao WHERE chave = ? AND usada = FALSE AND (valid_until > NOW() OR valid_until IS NULL)',
            [chave]
        );
        if (rows.length === 0) {
            return res.status(403).json({ message: 'Chave inválida ou expirada' });
        }
        await pool.query('UPDATE chaves_ativacao SET usada = TRUE, usada_em = NOW() WHERE chave = ?', [chave]);
        res.json({ message: 'Ativação bem-sucedida' });
    } catch (error) {
        console.error('Erro ao validar chave:', error.message);
        res.status(500).json({ message: 'Erro no servidor' });
    }
});

app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(3000, '0.0.0.0', () => {
    console.log('Server running on http://0.0.0.0:3000');
});