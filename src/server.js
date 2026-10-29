import { createServer } from 'node:http';
import { randomBytes, scrypt as scryptCallback, timingSafeEqual, createHmac } from 'node:crypto';
import { promisify } from 'node:util';

const scrypt = promisify(scryptCallback);
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || 'chave-local-troque-antes-de-publicar';
const TOKEN_TTL_SECONDS = 60 * 60 * 8;

// Repositórios provisórios em memória. Os dados são apagados ao reiniciar o processo.
const usuarios = [];
const pets = [];
const agendamentos = [];
let nextUsuarioId = 1;
let nextPetId = 1;
let nextAgendamentoId = 1;

function json(res, status, data) {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(data));
}

async function readBody(req) {
  let raw = '';
  for await (const chunk of req) {
    raw += chunk;
    if (raw.length > 1_000_000) throw Object.assign(new Error('Corpo da requisição muito grande.'), { status: 413 });
  }
  if (!raw) return {};
  try { return JSON.parse(raw); }
  catch { throw Object.assign(new Error('JSON inválido.'), { status: 400 }); }
}

function base64url(value) {
  return Buffer.from(value).toString('base64url');
}

function gerarToken(usuario) {
  const header = base64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const payload = base64url(JSON.stringify({
    sub: usuario.id,
    perfil: usuario.perfil,
    exp: Math.floor(Date.now() / 1000) + TOKEN_TTL_SECONDS,
  }));
  const assinatura = createHmac('sha256', JWT_SECRET).update(`${header}.${payload}`).digest('base64url');
  return `${header}.${payload}.${assinatura}`;
}

function validarToken(token) {
  const partes = token.split('.');
  if (partes.length !== 3) return null;
  const [header, payload, assinatura] = partes;
  const esperada = createHmac('sha256', JWT_SECRET).update(`${header}.${payload}`).digest();
  let recebida;
  try { recebida = Buffer.from(assinatura, 'base64url'); } catch { return null; }
  if (recebida.length !== esperada.length || !timingSafeEqual(recebida, esperada)) return null;
  try {
    const claims = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (!Number.isInteger(claims.sub) || claims.exp <= Math.floor(Date.now() / 1000)) return null;
    return claims;
  } catch { return null; }
}

function autenticar(req) {
  const [tipo, token] = (req.headers.authorization || '').split(' ');
  if (tipo?.toLowerCase() !== 'bearer' || !token) return null;
  const claims = validarToken(token);
  if (!claims) return null;
  const usuario = usuarios.find((item) => item.id === claims.sub);
  return usuario ? { id: usuario.id, perfil: usuario.perfil } : null;
}

function validarTexto(valor, campo, minimo = 1) {
  if (typeof valor !== 'string' || valor.trim().length < minimo) {
    throw Object.assign(new Error(`${campo} é obrigatório e deve ter pelo menos ${minimo} caractere(s).`), { status: 400 });
  }
  return valor.trim();
}

function usuarioPublico(usuario) {
  const { senhaHash, ...dados } = usuario;
  return dados;
}

async function registrar(body) {
  const nome = validarTexto(body.nome, 'Nome');
  const email = validarTexto(body.email, 'E-mail').toLowerCase();
  const senha = validarTexto(body.senha, 'Senha', 8);
  if (!/^\S+@\S+\.\S+$/.test(email)) throw Object.assign(new Error('E-mail inválido.'), { status: 400 });
  if (usuarios.some((usuario) => usuario.email === email)) throw Object.assign(new Error('E-mail já cadastrado.'), { status: 409 });
  const salt = randomBytes(16).toString('hex');
  const hash = await scrypt(senha, salt, 64);
  const usuario = { id: nextUsuarioId++, nome, email, senhaHash: `${salt}:${hash.toString('hex')}`, perfil: 'cliente' };
  usuarios.push(usuario);
  return usuario;
}

async function login(body) {
  const email = validarTexto(body.email, 'E-mail').toLowerCase();
  const senha = validarTexto(body.senha, 'Senha');
  const usuario = usuarios.find((item) => item.email === email);
  if (!usuario) return null;
  const [salt, hashSalvo] = usuario.senhaHash.split(':');
  const hashRecebido = await scrypt(senha, salt, 64);
  const hashEsperado = Buffer.from(hashSalvo, 'hex');
  if (hashRecebido.length !== hashEsperado.length || !timingSafeEqual(hashRecebido, hashEsperado)) return null;
  return usuario;
}

function rotaPet(pathname) {
  const match = pathname.match(/^\/api\/pets\/(\d+)$/);
  return match ? Number(match[1]) : null;
}

function rotaAgendamento(pathname) {
  const match = pathname.match(/^\/api\/agendamentos\/(\d+)$/);
  return match ? Number(match[1]) : null;
}

const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const { pathname } = url;
    const method = req.method || 'GET';

    if (method === 'GET' && pathname === '/api/health') return json(res, 200, { status: 'ok', armazenamento: 'memória' });

    if (method === 'POST' && pathname === '/api/auth/registrar') {
      const usuario = await registrar(await readBody(req));
      return json(res, 201, { usuario: usuarioPublico(usuario), token: gerarToken(usuario) });
    }
    if (method === 'POST' && pathname === '/api/auth/login') {
      const usuario = await login(await readBody(req));
      if (!usuario) return json(res, 401, { erro: 'E-mail ou senha inválidos.' });
      return json(res, 200, { usuario: usuarioPublico(usuario), token: gerarToken(usuario) });
    }
    if (method === 'GET' && pathname === '/api/auth/me') {
      const sessao = autenticar(req);
      if (!sessao) return json(res, 401, { erro: 'Token ausente ou inválido.' });
      const usuario = usuarios.find((item) => item.id === sessao.id);
      return json(res, 200, { usuario: usuarioPublico(usuario) });
    }

    // Os recursos abaixo exigem um token Bearer válido.
    const sessao = autenticar(req);
    if (!sessao) return json(res, 401, { erro: 'Token ausente ou inválido.' });

    if (pathname === '/api/pets' && method === 'GET') {
      return json(res, 200, pets.filter((pet) => pet.usuarioId === sessao.id));
    }
    if (pathname === '/api/pets' && method === 'POST') {
      const body = await readBody(req);
      const pet = {
        id: nextPetId++, usuarioId: sessao.id,
        nome: validarTexto(body.nome, 'Nome do pet'),
        especie: validarTexto(body.especie, 'Espécie'),
        raca: validarTexto(body.raca, 'Raça'),
      };
      pets.push(pet);
      return json(res, 201, pet);
    }
    const petId = rotaPet(pathname);
    if (petId && method === 'GET') {
      const pet = pets.find((item) => item.id === petId && item.usuarioId === sessao.id);
      return pet ? json(res, 200, pet) : json(res, 404, { erro: 'Pet não encontrado.' });
    }
    if (petId && method === 'DELETE') {
      const index = pets.findIndex((item) => item.id === petId && item.usuarioId === sessao.id);
      if (index < 0) return json(res, 404, { erro: 'Pet não encontrado.' });
      pets.splice(index, 1);
      return json(res, 204, null);
    }

    if (pathname === '/api/agendamentos' && method === 'GET') {
      const meusPets = new Set(pets.filter((pet) => pet.usuarioId === sessao.id).map((pet) => pet.id));
      return json(res, 200, agendamentos.filter((item) => meusPets.has(item.petId)));
    }
    if (pathname === '/api/agendamentos' && method === 'POST') {
      const body = await readBody(req);
      const petIdBody = Number(body.petId);
      if (!Number.isInteger(petIdBody) || !pets.some((pet) => pet.id === petIdBody && pet.usuarioId === sessao.id)) {
        throw Object.assign(new Error('Pet não encontrado para este usuário.'), { status: 400 });
      }
      const dataHora = new Date(body.dataHora);
      if (!body.dataHora || Number.isNaN(dataHora.getTime())) throw Object.assign(new Error('Data e hora inválidas.'), { status: 400 });
      const agendamento = {
        id: nextAgendamentoId++, petId: petIdBody, dataHora: dataHora.toISOString(),
        servico: validarTexto(body.servico, 'Serviço'), status: 'solicitado',
      };
      agendamentos.push(agendamento);
      return json(res, 201, agendamento);
    }
    const agendamentoId = rotaAgendamento(pathname);
    if (agendamentoId && method === 'DELETE') {
      const index = agendamentos.findIndex((item) => item.id === agendamentoId && pets.some((pet) => pet.id === item.petId && pet.usuarioId === sessao.id));
      if (index < 0) return json(res, 404, { erro: 'Agendamento não encontrado.' });
      agendamentos.splice(index, 1);
      return json(res, 204, null);
    }

    return json(res, 404, { erro: 'Rota não encontrada.' });
  } catch (error) {
    if (!res.headersSent) json(res, error.status || 500, { erro: error.status ? error.message : 'Erro interno do servidor.' });
  }
});

server.listen(PORT, () => console.log(`API Pet Shop disponível em http://localhost:${PORT}`));
