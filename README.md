# Minicurso de Segurança da Informação — 6 CTFs Web

Seis desafios web containerizados para prática: **4 fáceis** e **2 médios**. Cada desafio explora uma classe diferente de falha:

- confiança indevida em dados controlados pelo cliente (cookies);
- SQL Injection e bypass de autenticação;
- IDOR (referência direta insegura a objetos);
- Command Injection;
- SSTI (Server-Side Template Injection);
- SSRF (Server-Side Request Forgery).

Todas as aplicações são **intencionalmente vulneráveis**. Execute apenas em ambiente de laboratório.

## Desafios

| # | Desafio | Nível | Tema | URL local | Credenciais |
|---|---------|-------|------|-----------|-------------|
| 01 | Cookie Monsters | fácil | Cookie de sessão em base64 sem assinatura | http://localhost:8001 | `guest` / `guest` |
| 02 | SQLi Login | fácil | SQL Injection no login | http://localhost:8002 | `guest` / `guest` |
| 03 | NotasWeb | fácil | IDOR em notas privadas | http://localhost:8003 | `guest` / `guest` |
| 04 | NetCheck | fácil | Command Injection | http://localhost:8004 | — |
| 05 | TemplateLab | médio | SSTI / Jinja2 | http://localhost:8005 | — |
| 06 | URL Preview | médio | SSRF para serviço interno | http://localhost:8006 | — |

As flags estão no formato `flag{...}`.

## Requisitos

- Docker Engine 24 ou superior
- Docker Compose v2 ou superior

## Como subir

```bash
docker compose up --build -d
docker compose ps
```

Aguarde os serviços ficarem `healthy` e acesse as URLs da tabela.

Por padrão as portas são publicadas apenas em `127.0.0.1`. Para disponibilizar na rede local (por exemplo, os alunos acessarem pelo IP do servidor):

```bash
BIND_ADDR=0.0.0.0 docker compose up --build -d
```

Nesse caso, proteja o servidor com firewall e não exponha as portas diretamente na internet.

## Como parar

```bash
docker compose down
```

## Como resetar

```bash
docker compose down
docker compose up --build -d
```

O CTF 01 é stateless. O CTF 02 recria o banco SQLite em `/tmp` a cada recriação do container. Os CTFs 04 e 05 recriam o arquivo `/tmp/flag.txt` a partir da variável de ambiente `FLAG`. O CTF 06 recria o serviço interno de flags.

## Briefing — CTF 01: Cookie Monsters

O sistema tem uma área administrativa que revela a flag. A conta de demonstração `guest` não tem privilégios. Investigue como o servidor identifica o usuário e o seu papel.

**Dicas progressivas:**

1. Faça login com `guest` / `guest` e abra o painel.
2. Inspecione os cookies no DevTools do navegador (`Application` → `Cookies`). O painel também mostra o cookie atual e o JSON decodificado.
3. O valor do cookie `session` é texto codificado em base64.
4. Ao decodificar, você encontra um JSON com os campos `user` e `role`.

## Briefing — CTF 02: SQLi Login

O painel administrativo guarda a flag. O formulário de login consulta uma tabela `users` em SQLite. Descubra uma forma de entrar como administrador sem saber a senha.

**Dicas progressivas:**

1. Leia o código-fonte da página (comentários HTML) e observe como a aplicação descreve a consulta.
2. Teste caracteres especiais, como `'`, no campo de usuário e observe o comportamento.
3. A consulta monta a cláusula `WHERE` com o que você digita. Tente fazer a condição ser sempre verdadeira.
4. Comentários SQL (`--`) podem ignorar o restante da consulta.

## Briefing — CTF 03: NotasWeb

O NotasWeb é um bloco de notas privado. A conta `guest` possui uma nota. O administrador também possui notas, incluindo uma que contém a flag. O sistema deveria impedir que um usuário lesse a nota de outro.

**Dicas progressivas:**

1. Faça login com `guest` / `guest` e abra a sua nota.
2. Observe o formato da URL: `/notes/<id>`.
3. Os IDs das notas são sequenciais.
4. Teste acessar o ID de outra nota. O servidor verifica se ela pertence a você?

## Briefing — CTF 04: NetCheck

O NetCheck é uma ferramenta de diagnóstico de rede. O servidor executa um comando com o host informado e devolve a saída. Obtenha execução de comandos no servidor e leia o arquivo `/tmp/flag.txt`.

**Dicas progressivas:**

1. A entrada é passada para um comando executado pelo shell do servidor.
2. Caracteres como `;`, `&&` e `|` encadeiam comandos no shell.
3. Teste `localhost; id` e observe a saída.
4. Use o mesmo encadeamento para executar `cat /tmp/flag.txt`.

## Briefing — CTF 05: TemplateLab

O TemplateLab gera cartões personalizados com Jinja2. O nome informado é interpretado como parte do template no servidor. Obtenha execução de comandos e leia o arquivo `/tmp/flag.txt`.

**Dicas progressivas:**

1. A pré-visualização é renderizada no servidor como um template Jinja2.
2. Teste expressões como `{{ 7 * 7 }}`.
3. Pesquise como acessar objetos internos do Python a partir dos globals do Jinja2.
4. Use um objeto como `cycler` ou `lipsum` para chegar ao módulo `os` e executar comandos.
5. A flag está em `/tmp/flag.txt`.

## Briefing — CTF 06: URL Preview

O URL Preview busca o conteúdo de uma URL a partir do servidor. Existe um serviço interno chamado `flag-service` que guarda a flag, mas ele não está publicado no host. Faça o servidor acessar esse serviço e devolver a flag.

**Dicas progressivas:**

1. A requisição é feita pelo servidor, não pelo seu navegador.
2. A aplicação bloqueia `localhost` e `127.0.0.1`, mas não bloqueia nomes internos da rede Docker.
3. O serviço interno responde em `flag-service:8000`.
4. Informe a URL `http://flag-service:8000/flag` no formulário.

## Estrutura do projeto

```text
.
├── docker-compose.yml
├── README.md
├── GABARITO.md
├── ctf01-cookie/
│   ├── Dockerfile
│   ├── app.py
│   ├── requirements.txt
│   ├── static/style.css
│   └── templates/
├── ctf02-sqli/
│   ├── Dockerfile
│   ├── app.py
│   ├── requirements.txt
│   ├── static/style.css
│   └── templates/
├── ctf03-idor/
│   ├── Dockerfile
│   ├── app.py
│   ├── requirements.txt
│   ├── static/style.css
│   └── templates/
├── ctf04-cmdi/
│   ├── Dockerfile
│   ├── app.py
│   ├── requirements.txt
│   ├── static/style.css
│   └── templates/
├── ctf05-ssti/
│   ├── Dockerfile
│   ├── app.py
│   ├── requirements.txt
│   ├── static/style.css
│   └── templates/
└── ctf06-ssrf/
    ├── Dockerfile
    ├── app.py
    ├── flag_service.py
    ├── requirements.txt
    ├── static/style.css
    └── templates/
```

## Notas para o instrutor

- As soluções completas estão em [`GABARITO.md`](./GABARITO.md). Não distribua esse arquivo para os alunos.
- Distribua aos alunos apenas as URLs e os briefings. O código-fonte contém anotações do instrutor e aponta diretamente para as falhas.
- As flags são definidas no `docker-compose.yml`, nas variáveis `FLAG`. Para trocar uma flag, basta alterar o valor e recriar o serviço (`docker compose up -d --force-recreate <serviço>`), sem precisar rebuildar a imagem.
- Nos CTFs 04 e 05 a aplicação escreve a flag em `/tmp/flag.txt` no startup, a partir da variável `FLAG`.
- O CTF 06 tem um segundo container, `ctf06-flag-service`, sem porta publicada. Ele só é alcançável pela rede Docker. Não publique essa porta no host.
- Os containers já rodam com usuário não-root, filesystem somente leitura, `/tmp` em `tmpfs`, `no-new-privileges` e todas as capabilities removidas.
- As aplicações usam Gunicorn com um worker, adequado para o volume de um minicurso. Não é uma configuração de produção.
- Tempo estimado: 10 a 20 minutos por desafio fácil e 20 a 40 minutos por desafio médio.
- Sugestão de condução: apresente o conceito, deixe os alunos explorarem, depois discuta a causa raiz e a correção de cada falha.
