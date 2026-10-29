# API Pet Shop (primeira etapa)

Implementação inicial baseada no diagrama de classes. A autenticação, usuários, pets e agendamentos funcionam sem banco de dados: os registros ficam em memória e são perdidos quando o processo é reiniciado.

## Requisitos e execução

- Node.js 20 ou superior
- `npm start` para iniciar em `http://localhost:3000`
- Opcional: definir `PORT` e `JWT_SECRET` no ambiente. Em produção, configure um segredo forte para `JWT_SECRET`.

Não há dependências externas. Para criar um usuário:

```http
POST /api/auth/registrar
Content-Type: application/json

{"nome":"Ana Silva","email":"ana@example.com","senha":"senha1234"}
```

A resposta inclui um token Bearer. Envie `Authorization: Bearer <token>` nas rotas protegidas.

## Rotas implementadas

| Método | Rota | Acesso | Descrição |
| --- | --- | --- | --- |
| GET | `/api/health` | Público | Estado da API |
| POST | `/api/auth/registrar` | Público | Cadastra usuário e retorna token |
| POST | `/api/auth/login` | Público | Autentica e retorna token |
| GET | `/api/auth/me` | Token | Retorna o usuário autenticado |
| GET | `/api/pets` | Token | Lista os pets do usuário |
| POST | `/api/pets` | Token | Cadastra pet (`nome`, `especie`, `raca`) |
| GET | `/api/pets/:id` | Token | Consulta um pet do usuário |
| DELETE | `/api/pets/:id` | Token | Remove um pet do usuário |
| GET | `/api/agendamentos` | Token | Lista agendamentos dos pets do usuário |
| POST | `/api/agendamentos` | Token | Cria agendamento (`petId`, `dataHora`, `servico`) |
| DELETE | `/api/agendamentos/:id` | Token | Cancela removendo o agendamento |

Senhas são armazenadas com hash `scrypt`. O JWT é assinado com HS256 e expira em oito horas. O perfil inicial é `cliente`; autorização administrativa e edição de cadastros ficam para etapas posteriores.
