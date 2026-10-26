require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// ---------- Conexión a la base de datos (pool MySQL) ----------
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  port: Number(process.env.DB_PORT) || 3306,
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'localcash',
  dateStrings: true,      // DATE llega como "AAAA-MM-DD"
  decimalNumbers: true,   // DECIMAL llega como número
  waitForConnections: true,
  connectionLimit: 10
});
const SECRET = process.env.JWT_SECRET || 'cambia-este-secreto';
const sign = (id) => jwt.sign({ uid: id }, SECRET, { expiresIn: '7d' });

const app = express();
app.use(cors());
app.use(express.json());

const wrap = (fn) => (req, res) =>
  fn(req, res).catch((e) => { console.error(e); res.status(500).json({ error: 'Error interno del servidor' }); });
const bad = (res, msg, code = 400) => res.status(code).json({ error: msg });

// ---------- Salud ----------
app.get('/api/health', wrap(async (req, res) => {
  await pool.query('SELECT 1');
  res.json({ status: 'ok', db: 'conectada' });
}));

// ---------- Autenticación ----------
app.post('/api/auth/register', wrap(async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !/^\S+@\S+\.\S+$/.test(email)) return bad(res, 'Email inválido');
  if (!password || String(password).length < 4) return bad(res, 'La contraseña debe tener al menos 4 caracteres');
  const [ex] = await pool.query('SELECT id FROM usuarios WHERE email=?', [email]);
  if (ex.length) return bad(res, 'El email ya está registrado', 409);
  const hash = await bcrypt.hash(String(password), 10);
  const [r] = await pool.query('INSERT INTO usuarios(email,password_hash) VALUES(?,?)', [email, hash]);
  res.status(201).json({ token: sign(r.insertId), usuario: { id: r.insertId, email } });
}));

app.post('/api/auth/login', wrap(async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return bad(res, 'Email y contraseña son obligatorios');
  const [rows] = await pool.query('SELECT id,password_hash FROM usuarios WHERE email=?', [email]);
  if (!rows.length || !(await bcrypt.compare(String(password), rows[0].password_hash)))
    return bad(res, 'Credenciales incorrectas', 401);
  res.json({ token: sign(rows[0].id), usuario: { id: rows[0].id, email } });
}));

function auth(req, res, next) {
  const h = req.headers.authorization || '';
  if (!h.startsWith('Bearer ')) return bad(res, 'Falta el token de autenticación', 401);
  try { req.uid = jwt.verify(h.slice(7), SECRET).uid; next(); }
  catch (e) { bad(res, 'Token inválido o vencido', 401); }
}

// ---------- Saldos calculados por cuenta ----------
app.get('/api/cuentas/saldos', auth, wrap(async (req, res) => {
  const [rows] = await pool.query(
    `SELECT c.id, c.nombre,
            c.saldo_inicial + COALESCE(SUM(CASE WHEN m.tipo='I' THEN m.monto ELSE -m.monto END),0) AS saldo
     FROM cuentas c LEFT JOIN movimientos m ON m.cuenta_id=c.id
     WHERE c.usuario_id=? GROUP BY c.id, c.nombre ORDER BY c.nombre`, [req.uid]);
  res.json(rows);
}));

// ---------- CRUD genérico por recurso ----------
const RES = {
  contactos:   { fields: ['nombre', 'telefono'], required: ['nombre'] },
  cuentas:     { fields: ['nombre', 'saldo_inicial'], required: ['nombre'] },
  movimientos: { fields: ['cuenta_id', 'tipo', 'monto', 'descripcion', 'lat', 'lon', 'fecha'], required: ['cuenta_id', 'tipo', 'monto'] },
  compras:     { fields: ['descripcion', 'monto', 'fecha', 'estado', 'contacto_id', 'lat', 'lon'], required: ['descripcion', 'monto'] }
};
const FK = { cuenta_id: 'cuentas', contacto_id: 'contactos' };
const hoy = () => new Date().toISOString().slice(0, 10);

function crud(name, cfg) {
  const r = express.Router();
  r.use(auth);
  const clean = (b) => { const o = {}; for (const f of cfg.fields) if (b[f] !== undefined) o[f] = b[f]; return o; };
  const validate = (o, full) => {
    if (full) for (const f of cfg.required) if (o[f] == null || o[f] === '') return `Falta el campo ${f}`;
    if (o.tipo !== undefined && !['I', 'E'].includes(o.tipo)) return 'tipo debe ser I o E';
    if (o.estado !== undefined && !['AGENDADA', 'REALIZADA'].includes(o.estado)) return 'estado debe ser AGENDADA o REALIZADA';
    if (o.monto !== undefined && !(Number(o.monto) > 0)) return 'monto debe ser mayor a 0';
    if (o.fecha !== undefined && !/^\d{4}-\d{2}-\d{2}$/.test(o.fecha)) return 'fecha debe tener formato AAAA-MM-DD';
    return null;
  };
  const checkFk = async (uid, o) => {
    for (const k of Object.keys(FK)) if (o[k] != null) {
      const [x] = await pool.query(`SELECT id FROM ${FK[k]} WHERE id=? AND usuario_id=?`, [o[k], uid]);
      if (!x.length) return `${k} no existe`;
    }
    return null;
  };

  r.get('/', wrap(async (req, res) => {
    let sql = `SELECT * FROM ${name} WHERE usuario_id=?`; const p = [req.uid];
    if (name === 'movimientos' && req.query.cuenta_id) { sql += ' AND cuenta_id=?'; p.push(req.query.cuenta_id); }
    const [rows] = await pool.query(sql + ' ORDER BY id DESC', p);
    res.json(rows);
  }));

  r.get('/:id', wrap(async (req, res) => {
    const [rows] = await pool.query(`SELECT * FROM ${name} WHERE id=? AND usuario_id=?`, [req.params.id, req.uid]);
    rows.length ? res.json(rows[0]) : bad(res, 'No encontrado', 404);
  }));

  r.post('/', wrap(async (req, res) => {
    const o = clean(req.body || {});
    if (['movimientos', 'compras'].includes(name) && !o.fecha) o.fecha = hoy();
    const e = validate(o, true) || (await checkFk(req.uid, o));
    if (e) return bad(res, e);
    o.usuario_id = req.uid;
    const keys = Object.keys(o);
    const [ins] = await pool.query(`INSERT INTO ${name}(${keys.join(',')}) VALUES(${keys.map(() => '?').join(',')})`, keys.map((k) => o[k]));
    const [rows] = await pool.query(`SELECT * FROM ${name} WHERE id=?`, [ins.insertId]);
    res.status(201).json(rows[0]);
  }));

  r.put('/:id', wrap(async (req, res) => {
    const o = clean(req.body || {});
    const keys = Object.keys(o);
    if (!keys.length) return bad(res, 'No hay campos para actualizar');
    const e = validate(o, false) || (await checkFk(req.uid, o));
    if (e) return bad(res, e);
    const [u] = await pool.query(`UPDATE ${name} SET ${keys.map((k) => k + '=?').join(',')} WHERE id=? AND usuario_id=?`,
      [...keys.map((k) => o[k]), req.params.id, req.uid]);
    if (!u.affectedRows) return bad(res, 'No encontrado', 404);
    const [rows] = await pool.query(`SELECT * FROM ${name} WHERE id=?`, [req.params.id]);
    res.json(rows[0]);
  }));

  r.delete('/:id', wrap(async (req, res) => {
    const [d] = await pool.query(`DELETE FROM ${name} WHERE id=? AND usuario_id=?`, [req.params.id, req.uid]);
    d.affectedRows ? res.json({ eliminado: Number(req.params.id) }) : bad(res, 'No encontrado', 404);
  }));
  return r;
}
for (const [name, cfg] of Object.entries(RES)) app.use('/api/' + name, crud(name, cfg));

app.use((req, res) => bad(res, 'Ruta no encontrada', 404));

const PORT = Number(process.env.PORT) || 3000;
app.listen(PORT, '0.0.0.0', () => console.log(`LocalCash API escuchando en http://localhost:${PORT}  (prueba: /api/health)`));
