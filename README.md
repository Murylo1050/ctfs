# Minicurso de Segurança da Informação — 11 CTFs Web + VulnShop

Onze desafios web containerizados para prática: **6 fáceis**, **3 médios** e **2 difíceis**. Cada desafio explora uma classe diferente de falha:

- confiança indevida em dados controlados pelo cliente (cookies);
- SQL Injection e bypass de autenticação;
- IDOR (referência direta insegura a objetos);
- Command Injection;
- SSTI (Server-Side Template Injection);
- SSRF (Server-Side Request Forgery);
- Path Traversal / LFI (leitura arbitrária de arquivos);
- Mass Assignment (atribuição em massa de campos);
- XXE (XML External Entity);
- confusão de algoritmos em JWT;
- desserialização insegura com Python pickle.

Além dos desafios isolados, o laboratório inclui a **VulnShop**, uma aplicação de e-commerce completa que reúne várias falhas em um fluxo realista de compra.

Todas as aplicações são **intencionalmente vulneráveis**. Execute apenas em ambiente de laboratório.

## CTFs

| # | Desafio | Nível | Tema | URL local | Credenciais |
|---|---------|-------|------|-----------|-------------|
| 01 | Cookie Monsters | fácil | Cookie de sessão em base64 sem assinatura | http://localhost:8001 | `guest` / `guest` |
| 02 | SQLi Login | fácil | SQL Injection no login | http://localhost:8002 | `guest` / `guest` |
| 03 | NotasWeb | fácil | IDOR em notas privadas | http://localhost:8003 | `guest` / `guest` |
| 04 | NetCheck | fácil | Command Injection | http://localhost:8004 | — |
| 05 | TemplateLab | médio | SSTI / Jinja2 | http://localhost:8005 | — |
| 06 | URL Preview | médio | SSRF para serviço interno | http://localhost:8006 | — |
| 07 | DocViewer | fácil | Path Traversal / LFI | http://localhost:8007 | — |
| 08 | ProfileHub | fácil | Mass Assignment | http://localhost:8008 | `guest` / `guest` |
| 09 | ImportaXML | médio | XXE (XML External Entity) | http://localhost:8009 | — |
| 10 | Admin API | difícil | Confusão de algoritmos em JWT | http://localhost:8010 | `guest` / `guest` |
| 11 | Session Store | difícil | Desserialização insegura (pickle) | http://localhost:8011 | — |

As flags estão no formato `flag{...}`.

## VulnShop — aplicação integrada

A **VulnShop** é um mini e-commerce com vitrine, busca, cadastro, carrinho, checkout, pedidos, notas fiscais, painel administrativo e API. Diferente dos CTFs isolados, as falhas aparecem em um sistema só, com dados e fluxos compartilhados.

| Aplicação | Tema | URL local | Credenciais |
|-----------|------|-----------|-------------|
| VulnShop | SQLi, Command Injection, cookie sem assinatura, IDOR, BOLA, path traversal, XSS refletido, open redirect, mass assignment e CSRF | http://localhost:8012 | `demo` / `demo123` e `alice` / `alice123` |

A aplicação tem **6 flags principais** (`SQLI`, `CMDI`, `COOKIE`, `IDOR`, `BOLA` e `TRAVERSAL`) e desafios extras. O serviço interno `shipping-service` não publica porta no host e guarda apenas a flag de Command Injection.

O briefing do aluno está em [`vulnshop/README.md`](./vulnshop/README.md) e o gabarito completo em [`vulnshop/GABARITO.md`](./vulnshop/GABARITO.md).

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

O CTF 01 é stateless. O CTF 02 recria o banco SQLite em `/tmp` a cada recriação do container. Os CTFs 04, 05, 07, 09 e 11 recriam o arquivo `/tmp/flag.txt` a partir da variável de ambiente `FLAG`. Os CTFs 08 e 10 mantêm os dados em memória e reiniciam limpos. O CTF 06 recria o serviço interno de flags.

A VulnShop recria o banco SQLite `/tmp/vulnshop.db`, as notas fiscais e os arquivos de flag em `/tmp` a cada recriação do container. Para zerar cadastros, pedidos e carrinhos, recrie os serviços da loja:

```bash
docker compose up -d --force-recreate vulnshop shipping-service
```

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

O URL Preview busca o conteúdo de uma URL a partir do servidor. Existe um serviço interno que guarda a flag, mas ele não está publicado no host e o nome dele não é informado neste briefing. Descubra o nome do serviço e faça o servidor acessar o recurso protegido.

**Dicas progressivas:**

1. A requisição é feita pelo servidor, não pelo seu navegador.
2. Enumere a própria aplicação: `robots.txt`, o endpoint de diagnóstico `/debug` e o histórico de pré-visualizações.
3. O histórico e o diagnóstico revelam um hostname interno e a porta em que ele responde.
4. Acesse a raiz desse serviço interno: ele indica o caminho do recurso protegido.

## Briefing — CTF 07: DocViewer

O DocViewer é uma central de documentos internos. O endpoint de download recebe o nome do arquivo e devolve o conteúdo lido pelo servidor. Existe uma flag em `/tmp/flag.txt`, fora do diretório de documentos. Faça o servidor ler esse arquivo.

**Dicas progressivas:**

1. Abra um documento da lista e observe o parâmetro `file` na URL.
2. O valor informado é concatenado ao diretório `/app/documents`.
3. Sequências como `../` permitem subir na árvore de diretórios.
4. Tente ler `../../tmp/flag.txt`.

## Briefing — CTF 08: ProfileHub

O ProfileHub permite editar nome e e-mail do usuário. Cada conta possui um papel (`role`), e a área administrativa só é liberada para `admin`. A conta `guest` / `guest` é comum. Torne-se administrador sem alterar o banco de dados.

**Dicas progressivas:**

1. Faça login com `guest` / `guest` e abra o perfil.
2. Observe os campos enviados no `POST /profile` pelo DevTools.
3. O servidor copia para o registro todos os campos recebidos, não apenas nome e e-mail.
4. Adicione o campo `role=admin` ao corpo da requisição e recarregue o perfil.

## Briefing — CTF 09: ImportaXML

O ImportaXML recebe um catálogo de produtos em XML, processa o documento no servidor e mostra os campos interpretados. Existe uma flag em `/tmp/flag.txt`. Faça o parser ler esse arquivo e devolver o conteúdo na resposta.

**Dicas progressivas:**

1. Importe o XML de exemplo e veja como os campos são exibidos.
2. Pesquise sobre XXE (XML External Entity) e a diretiva `DOCTYPE`.
3. Declare uma entidade `SYSTEM` apontando para `file:///tmp/flag.txt`.
4. Referencie a entidade dentro de `<descricao>` e envie o documento.

## Briefing — CTF 10: Admin API

A Admin API usa tokens JWT assinados com RSA. A conta `guest` / `guest` recebe um token com papel `user`, mas a área administrativa exige `role: admin`. A chave pública de verificação está disponível em `/pubkey`. Forje um token aceito pelo servidor.

**Dicas progressivas:**

1. Faça login e inspecione o token no painel (header e payload em base64url).
2. O header usa `RS256` e o payload contém `"role": "user"`.
3. O servidor aceita tanto `RS256` quanto `HS256` com a mesma chave.
4. Assine um token `HS256` usando o conteúdo do arquivo PEM exposto em `/pubkey` como segredo HMAC, com `"role": "admin"`.

## Briefing — CTF 11: Session Store

O Session Store guarda as preferências do perfil em um cookie `profile` codificado em base64. O servidor usa Python `pickle` para restaurar o objeto. Existe uma flag em `/tmp/flag.txt`. Obtenha execução de código no servidor e faça a flag aparecer na página.

**Dicas progressivas:**

1. Inspecione o cookie `profile` e decodifique o valor em base64.
2. O conteúdo é um objeto Python serializado com `pickle`.
3. `pickle.loads` executa o método `__reduce__` de objetos ao desserializar.
4. Crie um payload que execute `cat /tmp/flag.txt` (por exemplo, com `subprocess.check_output`) e envie o base64 no formulário de restauração. O resultado é exibido na página.

## Briefing — VulnShop

A VulnShop é uma loja completa em http://localhost:8012. Explore o fluxo normal (login, busca, carrinho, checkout, pedidos, frete e notas fiscais) e investigue as decisões de implementação. Há **6 flags principais** e vulnerabilidades extras.

**Contas:** `demo` / `demo123` e `alice` / `alice123`. As credenciais do administrador não são fornecidas.

**Desafios principais:**

1. **Busca oculta (SQL Injection):** existe um produto interno que não aparece na vitrine. A busca pública monta a consulta SQL com a entrada do usuário. Encontre o registro oculto.
2. **Frete sob demanda (Command Injection):** o cálculo de frete é feito por um serviço interno de logística. Existe uma flag dentro desse container. Obtenha execução de comandos e leia `/tmp/flag.txt`.
3. **Sessão de administrador (cookie):** o servidor confia no cookie `shop_session` para saber quem é o usuário e qual é o papel dele. Torne-se administrador e abra `/admin`.
4. **Pedido alheio (IDOR):** a rota `/orders/<id>` mostra os detalhes de um pedido. Os IDs são sequenciais e a aplicação não confere o proprietário. Leia a observação de um pedido que não é seu.
5. **API de pedidos (BOLA):** a API usa `X-API-Key`. Sua chave aparece na página do perfil. O endpoint `/api/v1/orders/<id>` autentica a chave, mas não verifica a qual usuário o pedido pertence.
6. **Nota fiscal indiscreta (Path Traversal):** o download de notas fiscais aceita um nome de arquivo e só valida a extensão `.txt`. Saia do diretório de notas e leia a flag em `/tmp`.

**Vulnerabilidades extras:** XSS refletido na busca, open redirect no login, mass assignment no cadastro (`role`), CSRF nos formulários e senhas armazenadas em texto puro.

**Dicas progressivas:** consulte [`vulnshop/README.md`](./vulnshop/README.md). O gabarito fica em [`vulnshop/GABARITO.md`](./vulnshop/GABARITO.md) e não deve ser distribuído aos alunos.

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
├── ctf06-ssrf/
│   ├── Dockerfile
│   ├── app.py
│   ├── flag_service.py
│   ├── requirements.txt
│   ├── static/style.css
│   └── templates/
├── ctf07-lfi/
│   ├── Dockerfile
│   ├── app.py
│   ├── requirements.txt
│   ├── documents/
│   ├── static/style.css
│   └── templates/
├── ctf08-mass-assignment/
│   ├── Dockerfile
│   ├── app.py
│   ├── requirements.txt
│   ├── static/style.css
│   └── templates/
├── ctf09-xxe/
│   ├── Dockerfile
│   ├── app.py
│   ├── requirements.txt
│   ├── static/style.css
│   └── templates/
├── ctf10-jwt/
│   ├── Dockerfile
│   ├── app.py
│   ├── requirements.txt
│   ├── static/style.css
│   └── templates/
├── ctf11-deserialization/
│   ├── Dockerfile
│   ├── app.py
│   ├── requirements.txt
│   ├── static/style.css
│   └── templates/
└── vulnshop/
    ├── Dockerfile
    ├── shipping.Dockerfile
    ├── app.py
    ├── db.py
    ├── shipping_service.py
    ├── requirements.txt
    ├── scripts/
    │   └── frete.sh
    ├── static/
    │   └── style.css
    ├── templates/
    ├── README.md
    └── GABARITO.md
```

## Notas para o instrutor

- As soluções completas estão em [`GABARITO.md`](./GABARITO.md) e [`vulnshop/GABARITO.md`](./vulnshop/GABARITO.md). Não distribua esses arquivos para os alunos.
- Distribua aos alunos apenas as URLs e os briefings. O código-fonte contém anotações do instrutor e aponta diretamente para as falhas.
- As flags são definidas no `docker-compose.yml`, nas variáveis `FLAG`. Para trocar uma flag, basta alterar o valor e recriar o serviço (`docker compose up -d --force-recreate <serviço>`), sem precisar rebuildar a imagem.
- Nos CTFs 04, 05, 07, 09 e 11 a aplicação escreve a flag em `/tmp/flag.txt` no startup, a partir da variável `FLAG`.
- O CTF 06 tem um segundo container, `ctf06-flag-service`, sem porta publicada. Ele só é alcançável pela rede Docker. Não publique essa porta no host. O nome do serviço não é divulgado no briefing: os alunos precisam descobri-lo pelo histórico de pré-visualizações, pelo `/debug` ou pelo `robots.txt`.
- A VulnShop usa variáveis de flag separadas: `FLAG_SQLI`, `FLAG_ADMIN`, `FLAG_IDOR`, `FLAG_BOLA` e `FLAG_TRAVERSAL` no container `vulnshop`, e `FLAG_CMDI` apenas no container interno `shipping-service`.
- O `shipping-service` não publica porta no host e não tem acesso ao banco, às notas fiscais nem às demais flags. Isso evita que o Command Injection leia os outros segredos da aplicação. Não publique a porta 8000 desse serviço.
- As credenciais do administrador da VulnShop não são divulgadas. O caminho pretendido é adulterar o cookie `shop_session` ou usar o mass assignment no cadastro. A chave `X-API-Key` da conta `demo` aparece no perfil e na página `/api`; isso é intencional para o exercício de BOLA.
- A VulnShop também contém falhas extras (XSS refletido, open redirect, CSRF e senhas em texto puro) que podem ser discutidas sem flag.
- Os containers já rodam com usuário não-root, filesystem somente leitura, `/tmp` em `tmpfs`, `no-new-privileges` e todas as capabilities removidas.
- As aplicações usam Gunicorn com um worker, adequado para o volume de um minicurso. Não é uma configuração de produção.
- Tempo estimado: 10 a 20 minutos por desafio fácil, 20 a 40 minutos por desafio médio e 40 a 60 minutos por desafio difícil.
- Sugestão de condução: apresente o conceito, deixe os alunos explorarem, depois discuta a causa raiz e a correção de cada falha.
