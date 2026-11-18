/* ═══════════════════════════════════════════════════════════════════════
   ESTAÇÃO DE PESAGEM
   Um notebook na linha, com a balança e a coletora (leitor de código de
   barras) ligadas por USB. A tela /pesagem lê o peso em tempo real,
   confere com o peso cadastrado no produto da célula e, com o peso certo,
   pede para bipar o número de série. Cada pesagem fica gravada com
   célula, programação (OP), produto, série e peso.

   A estação fica ligada a uma célula do Cadenciador central: a contagem
   de peças pesadas é comparada com a meta e com a cadência (takt) da célula.
   Peso incorreto vira aviso de voz nos tablets da célula.
   ═══════════════════════════════════════════════════════════════════════ */

const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const { pool } = require('../db');
const { requireAdmin } = require('../middleware/auth');
const central = require('./cadenciador-central');

const ONLINE_SEG = 10;
const COOKIE = 'cadc_est';
const DEZ_ANOS = 10 * 365 * 24 * 60 * 60 * 1000;
const sha = t => crypto.createHash('sha256').update(String(t)).digest('hex');
const deviceOk = d => typeof d === 'string' && /^[A-Za-z0-9_-]{8,80}$/.test(d);
const texto = (v, max) => String(v == null ? '' : v).replace(/\s+/g, ' ').trim().slice(0, max);
const num = v => { const x = parseFloat(String(v == null ? '' : v).replace(',', '.')); return Number.isFinite(x) ? x : null; };
const arred = x => Math.round(x * 1000) / 1000;
const cookieEm = new Map();
const avisoEm = new Map();        // último aviso de voz "peso incorreto" por célula

/* ─────────────── credencial própria do notebook (fica ligado sem depender de login) ─────────────── */

function credencialDoPedido(req) {
  const h = req.headers || {};
  if (h['x-est-device'] && h['x-est-token']) return { device: String(h['x-est-device']), token: String(h['x-est-token']) };
  const m = /(?:^|;\s*)cadc_est=([^;]+)/.exec(h.cookie || '');
  if (!m) return null;
  let v = m[1]; try { v = decodeURIComponent(v); } catch (e) { /* usa como veio */ }
  const i = v.indexOf('.');
  return i > 0 ? { device: v.slice(0, i), token: v.slice(i + 1) } : null;
}
async function estacaoDaCredencial(req) {
  const c = credencialDoPedido(req);
  if (!c || !deviceOk(c.device) || !/^[a-f0-9]{32,96}$/.test(c.token)) return null;
  const r = await pool.query('SELECT id, device_id FROM cadc_estacoes WHERE device_id=$1 AND token_hash=$2', [c.device, sha(c.token)]);
  return r.rows[0] || null;
}
function gravarCookie(res, device, token) {
  res.cookie(COOKIE, `${device}.${token}`, {
    maxAge: DEZ_ANOS, httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', path: '/'
  });
}
/** Deixa passar quem está logado (menos o perfil PCP) OU um notebook com credencial válida. */
async function estacaoOuSessao(req, res, next) {
  if (req.session && req.session.userId) return next();
  try {
    const e = await estacaoDaCredencial(req);
    if (e) { req.estCred = e; return next(); }
  } catch (e) { console.error('pesagem credencial', e.message); return res.status(503).json({ error: 'Servidor indisponível, tentando de novo' }); }
  if ((req.originalUrl || '').startsWith('/api/')) return res.status(401).json({ error: 'Estação sem autorização. Faça o login uma vez neste computador.' });
  return res.redirect('/login');
}
const mesmaEstacao = (req, deviceId) =>
  !!(req.session && req.session.userId) || !!(req.estCred && req.estCred.device_id === deviceId);

async function garantirCredencial(req, res, estId, deviceId) {
  const atual = req.estCred || await estacaoDaCredencial(req);
  if (atual && atual.device_id === deviceId) {
    const semCookie = !/(?:^|;\s*)cadc_est=/.test(req.headers.cookie || '');
    if (semCookie || Date.now() - (cookieEm.get(deviceId) || 0) > 24 * 60 * 60 * 1000) {
      const c = credencialDoPedido(req);
      if (c) { gravarCookie(res, deviceId, c.token); cookieEm.set(deviceId, Date.now()); }
    }
    return null;
  }
  if (!(req.session && req.session.userId)) return null;
  const r = await pool.query(
    `SELECT (token_em IS NOT NULL AND token_em > NOW() - INTERVAL '60 seconds') AS recente FROM cadc_estacoes WHERE id=$1`, [estId]);
  if (r.rows[0] && r.rows[0].recente) return null;
  const token = crypto.randomBytes(24).toString('hex');
  await pool.query('UPDATE cadc_estacoes SET token_hash=$2, token_em=NOW() WHERE id=$1', [estId, sha(token)]);
  gravarCookie(res, deviceId, token);
  return token;
}

/* ─────────────── regras de peso e de número de série ─────────────── */

/** Faixa de peso aceita para o produto: { padrao, tol, min, max } ou null se o produto não tem peso cadastrado. */
function faixaDoProduto(prod) {
  const padrao = prod && prod.peso_kg > 0 ? Number(prod.peso_kg) : null;
  if (!padrao) return null;
  // sem tolerância cadastrada: 2 % do peso, no mínimo 50 g
  const tol = prod.peso_tol_kg != null && prod.peso_tol_kg >= 0 ? Number(prod.peso_tol_kg) : Math.max(0.05, arred(padrao * 0.02));
  return { padrao, tol, min: arred(padrao - tol), max: arred(padrao + tol) };
}
const limparSerie = v => String(v == null ? '' : v).trim().toUpperCase().replace(/\s+/g, '');

/** Confere a série bipada com a faixa da OP da célula. Devolve { erro } ou { fora_faixa }. */
function conferirSerie(serie, ordem) {
  if (!/^[A-Z0-9][A-Z0-9\-_/.]{3,39}$/.test(serie)) return { erro: 'Código lido não parece um número de série. Bipe de novo.' };
  const ini = ordem && ordem.serie_inicial, fim = ordem && ordem.serie_final;
  if (!ini) return { fora_faixa: false };
  if (serie.length !== ini.length) return { erro: `Número de série deve ter ${ini.length} caracteres (lido: ${serie.length}). Bipe a etiqueta de série.` };
  const desdeInicio = central.qtdEntreSeries(ini, serie);
  if (desdeInicio == null) return { erro: `Esta série não é desta OP (esperado começar como ${ini.slice(0, Math.max(1, ini.length - 5))}…).` };
  let fora = desdeInicio < 1;
  if (!fora && fim) { const ateFim = central.qtdEntreSeries(serie, fim); fora = ateFim != null && ateFim < 1; }
  return { fora_faixa: fora };
}

async function contagem(ordemId) {
  if (!ordemId) return { ok: 0, nok: 0 };
  const r = await pool.query(
    `SELECT COUNT(*) FILTER (WHERE serie IS NOT NULL)::int AS ok,
            COUNT(*) FILTER (WHERE serie IS NULL AND ok = FALSE)::int AS nok
       FROM cadc_pesagens WHERE ordem_id=$1`, [ordemId]);
  return r.rows[0];
}
async function ultimas(ordemId, n = 8) {
  if (!ordemId) return [];
  return (await pool.query(
    `SELECT id, serie, peso_kg::float AS peso_kg, ok, fora_faixa,
            to_char(criado_em AT TIME ZONE '${central.FUSO}', 'HH24:MI:SS') AS hora
       FROM cadc_pesagens WHERE ordem_id=$1 ORDER BY id DESC LIMIT $2`, [ordemId, n])).rows;
}

async function estacaoDoPedido(req, deviceId) {
  if (!deviceOk(deviceId)) { const e = new Error('Identificação da estação inválida'); e.status = 400; throw e; }
  if (!mesmaEstacao(req, deviceId)) { const e = new Error('Estação sem autorização'); e.status = 401; throw e; }
  return (await pool.query('SELECT * FROM cadc_estacoes WHERE device_id=$1', [deviceId])).rows[0] || null;
}
const falha = (res, e, onde) => {
  if (!e.status) console.error('pesagem ' + onde, e);
  res.status(e.status || 500).json({ error: e.message });
};

/* ═════════════════════ TELA DO NOTEBOOK ═════════════════════ */

/* GET /estado?device_id=&nome=&balanca=0|1&peso= — tudo o que a tela precisa, consultado a cada 2 s */
router.get('/estado', estacaoOuSessao, async (req, res) => {
  try {
    const { device_id } = req.query;
    let est = await estacaoDoPedido(req, device_id);
    const logado = !!(req.session && req.session.userId);
    const peso = num(req.query.peso);
    if (!est) {
      const nome = texto(req.query.nome, 120) || ('Balança ' + device_id.slice(-4).toUpperCase());
      est = (await pool.query(
        `INSERT INTO cadc_estacoes (device_id, nome, usuario, visto_em) VALUES ($1,$2,$3,NOW())
         ON CONFLICT (device_id) DO UPDATE SET visto_em=NOW() RETURNING *`,
        [device_id, nome, logado ? req.session.username || null : null])).rows[0];
    } else {
      await pool.query(
        `UPDATE cadc_estacoes SET visto_em=NOW(), balanca_ok=$2, ultimo_peso=$3, usuario=COALESCE($4, usuario) WHERE id=$1`,
        [est.id, req.query.balanca === '1', peso != null && Math.abs(peso) < 100000 ? arred(peso) : null,
         logado ? req.session.username || null : null]);
    }
    const token = await garantirCredencial(req, res, est.id, device_id);
    const celulas = (await pool.query('SELECT id, nome, (ordem_id IS NOT NULL) AS rodando FROM cadc_celulas ORDER BY nome')).rows;

    let celula = null, ult = [];
    if (est.celula_id) {
      celula = await central.umaCelula(est.celula_id);
      if (celula) {
        celula.faixa = faixaDoProduto(celula.produto);
        ult = await ultimas(celula.ordem && celula.ordem.id);
        // a grade de ciclos é pesada: só vai quando algo mudou
        if (req.query.v && String(req.query.v) === celula.sinal) { delete celula.ciclos; delete celula.turno; delete celula.marcas; delete celula.anteriores; celula.igual = true; }
      }
    }
    res.json({ ...central.relogio(), ...(token ? { token } : {}),
               estacao: { id: est.id, nome: est.nome, celula_id: celula ? est.celula_id : null },
               celulas, celula, ultimas: ult });
  } catch (e) { falha(res, e, 'estado'); }
});

/* POST /estacao  body: { device_id, celula_id?, nome? } — o notebook escolhe a célula / muda o próprio nome */
router.post('/estacao', estacaoOuSessao, async (req, res) => {
  try {
    const b = req.body || {};
    const est = await estacaoDoPedido(req, b.device_id);
    if (!est) return res.status(404).json({ error: 'Estação ainda não registrada' });
    if ('celula_id' in b) {
      const id = b.celula_id ? Number(b.celula_id) : null;
      if (id && !(await pool.query('SELECT 1 FROM cadc_celulas WHERE id=$1', [id])).rowCount) return res.status(404).json({ error: 'Célula não encontrada' });
      await pool.query('UPDATE cadc_estacoes SET celula_id=$2 WHERE id=$1', [est.id, id]);
    }
    if (b.nome != null && texto(b.nome, 120)) await pool.query('UPDATE cadc_estacoes SET nome=$2 WHERE id=$1', [est.id, texto(b.nome, 120)]);
    res.json({ success: true });
  } catch (e) { falha(res, e, 'estacao'); }
});

/** Célula e programação em que a estação está pesando agora (ou erro explicando por que não dá). */
async function contexto(req, deviceId) {
  const est = await estacaoDoPedido(req, deviceId);
  const erro = (st, msg) => { const e = new Error(msg); e.status = st; return e; };
  if (!est) throw erro(404, 'Estação ainda não registrada');
  if (!est.celula_id) throw erro(409, 'Esta estação não está ligada a nenhuma célula');
  const cel = await central.umaCelula(est.celula_id);
  if (!cel) throw erro(409, 'A célula desta estação não existe mais');
  if (!cel.ordem || !cel.produto) throw erro(409, 'A célula está sem programação rodando. Peça ao administrador para iniciar.');
  return { est, cel };
}

async function gravar(est, cel, req, { serie, peso, ok, fora }) {
  const f = faixaDoProduto(cel.produto);
  const r = await pool.query(
    `INSERT INTO cadc_pesagens (celula_id, celula_nome, ordem_id, produto_id, produto_nome, cod_decio, num_op, serie,
                                peso_kg, peso_padrao, tolerancia, ok, fora_faixa, data, turno_id, estacao_id, estacao_nome, usuario)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
     RETURNING id, to_char(criado_em AT TIME ZONE '${central.FUSO}', 'HH24:MI:SS') AS hora`,
    [cel.id, cel.nome, cel.ordem.id, cel.produto.id, cel.produto.nome, cel.ordem.cod_decio || cel.produto.cod_decio || null,
     cel.ordem.num_op || null, serie, arred(peso), f ? f.padrao : null, f ? f.tol : null, ok, !!fora,
     cel.dia || cel.ordem.dia || central.dataFabrica(), cel.turno ? cel.turno.id : null, est.id, est.nome,
     (req.session && (req.session.nome || req.session.username)) || est.usuario || null]);
  return r.rows[0];
}

/* POST /registrar  body: { device_id, serie, peso_kg } — peso certo + série bipada = peça contada */
router.post('/registrar', estacaoOuSessao, async (req, res) => {
  try {
    const b = req.body || {};
    const { est, cel } = await contexto(req, b.device_id);
    const peso = num(b.peso_kg);
    if (peso == null || peso <= 0 || peso > 99999) return res.status(400).json({ error: 'Peso inválido. Confira a balança.' });
    const f = faixaDoProduto(cel.produto);
    if (f && (peso < f.min - 1e-9 || peso > f.max + 1e-9)) {
      return res.status(422).json({ error: 'Peso incorreto: não registrado.', incorreto: true });
    }
    const serie = limparSerie(b.serie);
    const conf = conferirSerie(serie, cel.ordem);
    if (conf.erro) return res.status(400).json({ error: conf.erro, serie_invalida: true });

    let linha;
    try {
      linha = await gravar(est, cel, req, { serie, peso, ok: f ? true : null, fora: conf.fora_faixa });
    } catch (e) {
      if (e.code !== '23505') throw e;
      const d = (await pool.query(
        `SELECT celula_nome, peso_kg::float AS peso_kg, to_char(criado_em AT TIME ZONE '${central.FUSO}', 'DD/MM HH24:MI') AS quando
           FROM cadc_pesagens WHERE serie=$1`, [serie])).rows[0] || {};
      return res.status(409).json({ error: `Série ${serie} já foi pesada (${d.quando || '?'}${d.celula_nome ? ', ' + d.celula_nome : ''}). Não contou de novo.`, duplicada: true });
    }
    res.json({ success: true, id: Number(linha.id), hora: linha.hora, serie, peso_kg: arred(peso), fora_faixa: !!conf.fora_faixa,
               contagem: await contagem(cel.ordem.id), ultimas: await ultimas(cel.ordem.id) });
  } catch (e) { falha(res, e, 'registrar'); }
});

/* POST /incorreto  body: { device_id, peso_kg } — produto com peso fora da faixa: grava e avisa os tablets da célula por voz */
router.post('/incorreto', estacaoOuSessao, async (req, res) => {
  try {
    const b = req.body || {};
    const { est, cel } = await contexto(req, b.device_id);
    const peso = num(b.peso_kg);
    const f = faixaDoProduto(cel.produto);
    if (peso == null || !f) return res.status(400).json({ error: 'Sem peso para conferir' });
    if (peso >= f.min && peso <= f.max) return res.json({ success: true, ignorado: true });
    await gravar(est, cel, req, { serie: null, peso, ok: false, fora: false });
    let falou = false;
    if (Date.now() - (avisoEm.get(cel.id) || 0) > 5000) {       // não repete o aviso em cima do outro
      avisoEm.set(cel.id, Date.now());
      await central.comando(cel.id, { texto: 'Peso incorreto', origem: 'balanca', por: est.nome });
      falou = true;
    }
    res.json({ success: true, falou, contagem: await contagem(cel.ordem.id), ultimas: await ultimas(cel.ordem.id) });
  } catch (e) { falha(res, e, 'incorreto'); }
});

/* ═════════════════════ ADMINISTRADOR ═════════════════════ */

/* GET /admin/lista?celula_id=&ordem_id=&dia=&de=&ate=&serie= — pesagens gravadas */
router.get('/admin/lista', requireAdmin, async (req, res) => {
  try {
    const q = req.query, cond = [], p = [];
    const DATA = /^\d{4}-\d{2}-\d{2}$/;
    if (q.ordem_id) { p.push(Number(q.ordem_id)); cond.push(`g.ordem_id=$${p.length}`); }
    if (q.celula_id) { p.push(Number(q.celula_id)); cond.push(`g.celula_id=$${p.length}`); }
    if (DATA.test(q.dia || '')) { p.push(q.dia); cond.push(`g.data=$${p.length}`); }
    if (DATA.test(q.de || '')) { p.push(q.de); cond.push(`g.data>=$${p.length}`); }
    if (DATA.test(q.ate || '')) { p.push(q.ate); cond.push(`g.data<=$${p.length}`); }
    if (q.serie) { p.push('%' + limparSerie(q.serie) + '%'); cond.push(`g.serie LIKE $${p.length}`); }
    const r = await pool.query(
      `SELECT g.id, g.celula_id, g.celula_nome, g.ordem_id, g.produto_nome, g.cod_decio, g.num_op, g.serie,
              g.peso_kg::float AS peso_kg, g.peso_padrao::float AS peso_padrao, g.tolerancia::float AS tolerancia,
              g.ok, g.fora_faixa, to_char(g.data,'YYYY-MM-DD') AS dia, g.estacao_nome, g.usuario,
              to_char(g.criado_em AT TIME ZONE '${central.FUSO}', 'HH24:MI:SS') AS hora
         FROM cadc_pesagens g ${cond.length ? 'WHERE ' + cond.join(' AND ') : ''}
        ORDER BY g.id DESC LIMIT 1000`, p);
    res.json(r.rows.map(x => ({ ...x, id: Number(x.id) })));
  } catch (e) { falha(res, e, 'lista'); }
});

/* DELETE /admin/pesagens/:id — apaga uma pesagem lançada errada (a série pode ser pesada de novo) */
router.delete('/admin/pesagens/:id', requireAdmin, async (req, res) => {
  try {
    const r = await pool.query('DELETE FROM cadc_pesagens WHERE id=$1', [req.params.id]);
    if (!r.rowCount) return res.status(404).json({ error: 'Pesagem não encontrada' });
    res.json({ success: true });
  } catch (e) { falha(res, e, 'apagar'); }
});

/* PUT /admin/estacoes/:id  body: { celula_id?, nome? } — o admin liga o notebook a uma célula pelo PC */
router.put('/admin/estacoes/:id', requireAdmin, async (req, res) => {
  try {
    const b = req.body || {};
    const est = (await pool.query('SELECT id FROM cadc_estacoes WHERE id=$1', [req.params.id])).rows[0];
    if (!est) return res.status(404).json({ error: 'Estação não encontrada' });
    if ('celula_id' in b) {
      const id = b.celula_id ? Number(b.celula_id) : null;
      if (id && !(await pool.query('SELECT 1 FROM cadc_celulas WHERE id=$1', [id])).rowCount) return res.status(404).json({ error: 'Célula não encontrada' });
      await pool.query('UPDATE cadc_estacoes SET celula_id=$2 WHERE id=$1', [est.id, id]);
    }
    if (b.nome != null && texto(b.nome, 120)) await pool.query('UPDATE cadc_estacoes SET nome=$2 WHERE id=$1', [est.id, texto(b.nome, 120)]);
    res.json({ success: true });
  } catch (e) { falha(res, e, 'estacao admin'); }
});

/* DELETE /admin/estacoes/:id — tira o notebook da lista (cancela a credencial dele) */
router.delete('/admin/estacoes/:id', requireAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM cadc_estacoes WHERE id=$1', [req.params.id]);
    res.json({ success: true });
  } catch (e) { falha(res, e, 'estacao apagar'); }
});

/* PUT /admin/produtos/:id/peso  body: { peso_kg, peso_tol_kg } — peso padrão do produto (vazio = não confere peso) */
router.put('/admin/produtos/:id/peso', requireAdmin, async (req, res) => {
  try {
    const peso = num(req.body && req.body.peso_kg), tol = num(req.body && req.body.peso_tol_kg);
    if (peso != null && (peso < 0 || peso > 99999)) return res.status(400).json({ error: 'Peso inválido' });
    if (tol != null && (tol < 0 || tol > 99999)) return res.status(400).json({ error: 'Tolerância inválida' });
    const r = await pool.query(
      `UPDATE cad_produtos SET peso_kg=$2, peso_tol_kg=$3, updated_at=NOW() WHERE id=$1
       RETURNING id, nome, peso_kg::float AS peso_kg, peso_tol_kg::float AS peso_tol_kg`,
      [req.params.id, peso > 0 ? arred(peso) : null, peso > 0 && tol != null ? arred(tol) : null]);
    if (!r.rowCount) return res.status(404).json({ error: 'Produto não encontrado' });
    res.json({ ...r.rows[0], faixa: faixaDoProduto(r.rows[0]) });
  } catch (e) { falha(res, e, 'peso produto'); }
});

router.estacaoOuSessao = estacaoOuSessao;
module.exports = router;
