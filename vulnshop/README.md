# VulnShop — mini e-commerce vulnerável

A **VulnShop** é uma aplicação de e-commerce completa, criada para o minicurso de segurança da informação. Ela tem vitrine, busca, cadastro, carrinho, checkout, pedidos, notas fiscais, painel administrativo e API — e contém falhas propositais em fluxos realistas.

> **Atenção:** esta aplicação é intencionalmente vulnerável. Execute apenas em ambiente de laboratório, nunca em produção ou exposta à internet.

## Como acessar

Com o laboratório no ar:

```bash
docker compose up --build -d
docker compose ps
```

- URL: **http://localhost:8012**
- Conta de demonstração: `demo` / `demo123`
- Segunda conta: `alice` / `alice123`
- A senha do administrador **não é fornecida**.

Se o instrutor configurou `BIND_ADDR=0.0.0.0`, use o IP do servidor em vez de `localhost`.

## O que explorar

A loja tem um fluxo normal que deve ser percorrido antes dos desafios:

1. Faça login com `demo`.
2. Busque produtos, abra um produto e adicione ao carrinho.
3. Finalize uma compra e abra o pedido gerado.
4. Baixe a nota fiscal.
5. Calcule o frete por CEP.
6. Abra o perfil e veja a chave da API.
7. Consulte a documentação em `/api`.

Você também pode criar sua própria conta em `/register`.

## Desafios principais

As flags estão no formato `flag{...}`. São **6 flags principais**, cada uma em um ponto diferente da aplicação.

### 1. Busca oculta — SQL Injection

A busca pública de produtos monta uma consulta SQL com o texto digitado. Existe um produto interno que não aparece na vitrine e cuja descrição contém uma flag.

**Objetivo:** fazer a busca retornar o registro que não deveria ser público.

**Dicas progressivas:**

1. Busque por termos normais (`fone`, `teclado`) e observe a URL `/search?q=...`.
2. Teste uma aspa simples (`'`) e compare o comportamento com uma busca válida.
3. A consulta usa `LIKE` com o termo interpolado. Pense em como encerrar a cláusula e juntar outra consulta.
4. O produto oculto está na mesma tabela, mas com `visible = 0`. A consulta legitima filtra `visible = 1`.
5. Monte um `UNION SELECT` com a mesma quantidade de colunas da consulta original.

### 2. Frete sob demanda — Command Injection

O cálculo de frete é processado por um serviço interno de logística, acessível pela página `/shipping`. A flag desse desafio está dentro do container do serviço de frete, em `/tmp/flag.txt`.

**Objetivo:** obter execução de comandos no serviço de frete e ler a flag.

**Dicas progressivas:**

1. Faça login e envie um CEP válido, como `01310-100`, em `/shipping`.
2. O campo de CEP é repassado para uma ferramenta de linha de comando no servidor.
3. Teste separadores de shell (`;`, `&&`, `|`) e comandos simples, como `id` ou `whoami`.
4. Use o mesmo encadeamento para executar `cat /tmp/flag.txt`.
5. A saída do comando aparece no resultado do cálculo.

Esse serviço é isolado do banco e das demais flags. Não tente acessar o banco da loja a partir dele.

### 3. Sessão de administrador — cookie sem assinatura

O servidor guarda a sessão no cookie `shop_session`. O conteúdo é um JSON codificado em base64, mas **não é assinado**. A área `/admin` decide se o usuário é administrador com base apenas nesse cookie.

**Objetivo:** acessar o painel administrativo e obter a flag.

**Dicas progressivas:**

1. Faça login com `demo` e abra o DevTools (`Application` → `Cookies`).
2. Decodifique o valor de `shop_session` em base64.
3. Você encontrará campos como `uid`, `username` e `role`.
4. Altere o papel para `admin`, recodifique em base64 e substitua o cookie no navegador.
5. Recarregue `/admin`.

O cookie também está acessível via JavaScript (`HttpOnly` desativado). Isso é proposital e se conecta ao desafio de XSS.

### 4. Pedido alheio — IDOR

A rota `/orders/<id>` mostra os detalhes de um pedido. Os IDs são sequenciais. A aplicação verifica se você está logado, mas não se o pedido pertence à sua conta.

**Objetivo:** ler a observação de um pedido que não é seu e encontrar a flag.

**Dicas progressivas:**

1. Faça login com `demo` e abra `/orders`.
2. Observe o ID do seu pedido e o formato da URL.
3. Tente IDs vizinhos, como `1001`, `1003` e `1004`.
4. Um dos pedidos pertence a outro usuário e contém uma observação de atendimento com a flag.

### 5. API de pedidos — BOLA

A API usa a chave pessoal no cabeçalho `X-API-Key`. A chave da conta `demo` aparece na página `/profile` e na documentação `/api`.

**Objetivo:** consultar pela API um pedido que não pertence ao dono da chave e obter a nota interna com a flag.

**Dicas progressivas:**

1. Abra `/api` e leia a documentação.
2. Consulte `GET /api/v1/orders/1002` com a chave de `demo`.
3. O endpoint autentica a chave, mas não confere se o pedido pertence ao usuário.
4. Teste outros IDs de pedido. A resposta inclui o campo `internal_note`.
5. Um pedido administrativo contém uma nota interna sensível.

### 6. Nota fiscal indiscreta — Path Traversal

O download de notas fiscais aceita um nome de arquivo no parâmetro `file` e valida apenas se o nome termina em `.txt`. As notas ficam em `/tmp/invoices`; a flag está em `/tmp/invoice-flag.txt`.

**Objetivo:** sair do diretório de notas e ler o arquivo com a flag.

**Dicas progressivas:**

1. Abra um pedido e clique em “Baixar nota fiscal”.
2. Observe a URL `/invoices/download?file=invoice-1002.txt`.
3. O servidor junta o diretório de notas com o nome informado, sem normalizar o caminho.
4. Use `../` para subir um nível e acessar `invoice-flag.txt`.
5. A extensão `.txt` precisa ser mantida.

## Vulnerabilidades extras

Não têm flag própria, mas são ótimos temas de discussão:

- **XSS refletido:** o termo de busca é devolvido sem escape na página de resultados. Teste com uma tag `<script>`.
- **Open redirect:** o login aceita o parâmetro `next` e redireciona para qualquer URL, inclusive externa.
- **Mass assignment:** o cadastro aceita o campo `role`. Envie `role=admin` no corpo do `POST /register`.
- **CSRF:** carrinho, checkout e logout não usam token anti-CSRF.
- **Senhas em texto puro:** o banco guarda as senhas sem hash (a aplicação é didática).
- **Chave de API exposta:** a chave pessoal aparece na página de perfil e a chave de `demo` aparece na documentação pública.
- **Autorização no cliente:** o menu “Admin” e o painel confiam no papel do cookie.

## Mapa de endpoints

| Método | Rota | Descrição |
|--------|------|-----------|
| GET | `/` | Vitrine |
| GET | `/products` | Catálogo e filtro por categoria |
| GET | `/search?q=` | Busca pública |
| GET | `/product/<id>` | Detalhe do produto |
| GET/POST | `/login` | Login (aceita `next`) |
| GET/POST | `/register` | Cadastro |
| GET | `/logout` | Encerra a sessão |
| GET | `/profile` | Perfil e chave de API |
| GET | `/cart` | Carrinho |
| POST | `/cart/add` | Adiciona item |
| POST | `/cart/update` | Atualiza quantidade |
| POST | `/cart/remove` | Remove item |
| GET/POST | `/checkout` | Finaliza a compra |
| GET | `/orders` | Pedidos do usuário |
| GET | `/orders/<id>` | Detalhe do pedido |
| GET | `/invoices/download?file=` | Download de nota fiscal |
| GET/POST | `/shipping` | Cálculo de frete |
| GET | `/admin` | Painel administrativo |
| GET | `/api` | Documentação da API |
| GET | `/api/v1/orders/<id>` | Consulta de pedido via `X-API-Key` |
| GET | `/health` | Healthcheck |

## Resetar o ambiente

Os dados ficam em `/tmp` (tmpfs). Para zerar cadastros, pedidos, carrinhos e arquivos:

```bash
docker compose up -d --force-recreate vulnshop shipping-service
```

Para parar tudo:

```bash
docker compose down
```

## Estrutura

```text
vulnshop/
├── Dockerfile             # imagem da loja
├── shipping.Dockerfile    # imagem isolada do serviço de frete
├── app.py                 # aplicação principal (Flask + SQLite)
├── db.py                  # schema, seed e geração das notas fiscais
├── shipping_service.py    # serviço interno de frete
├── scripts/frete.sh       # calculadora chamada pelo serviço
├── static/style.css
├── templates/
├── requirements.txt
├── README.md              # este arquivo
└── GABARITO.md            # material do instrutor
```

## Ética e escopo

Use apenas este laboratório e os dados fictícios fornecidos. As técnicas aqui praticadas devem ser aplicadas somente em sistemas com autorização explícita. O objetivo é aprender a identificar, explorar e corrigir falhas — não atacar sistemas de terceiros.
