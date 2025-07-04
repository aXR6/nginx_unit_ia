# Nginx Unit IA

Este projeto adiciona uma camada de segurança ao [Nginx Unit](https://unit.nginx.org/) utilizando modelos de linguagem do HuggingFace. Todas as requisições passam por um proxy em Python que analisa e classifica o conteúdo antes de encaminhar ao Nginx Unit. Logs e IPs suspeitos podem ser armazenados em PostgreSQL e consultados por um painel web.

## Funcionalidades

- Classifica severidade, anomalias e categorias de rede (NIDS) de cada requisição.
- Detecção semântica de comportamentos fora do padrão através de embeddings.
- Bloqueio automático de IPs suspeitos com integração ao firewall **UFW**.
- Painel web em Flask/Bootstrap com logs em tempo real e lista de IPs bloqueados.
- Painel web em Flask/Bootstrap com paginação (100 itens por página), logs coloridos por categoria e exibição do modelo utilizado.
- Cálculo de intensidade de ataque combinando resultados dos modelos.
- Visualização detalhada de cada log com todas as informações classificadas.
- Barra superior exibe informações resumidas dos modelos carregados.
- Registro opcional em banco PostgreSQL com esquema definido em `schema.sql`.
- Script interativo (`python -m app.menu`) para iniciar/parar o proxy e o painel, além de selecionar CPU ou GPU para inferência.
- Conjunto de regex robustos para detectar XSS, SQLi, SSRF, XXE, brute force, malware e diversos outros ataques, com fallback para modelo de linguagem e cuidado contra ReDoS.

## Instalação

1. Copie `.env.example` para `.env` e ajuste as variáveis conforme o ambiente.
2. Instale as dependências do Python:
   ```bash
   pip install -r requirements.txt
   ```
3. (Opcional) Suba o contêiner do Nginx Unit e da aplicação de exemplo:
   ```bash
   docker-compose up -d
   ```

## Uso

Execute o menu interativo para controlar o proxy e o painel:

```bash
python -m app.menu
```

O proxy escutará na porta configurada em `UNIT_PORT` e encaminhará as requisições para `BACKEND_URL`. Esse backend normalmente é o serviço do Nginx Unit exposto na porta `UNIT_BACKEND_PORT`. O painel estará disponível em `http://localhost:8080` (ou porta definida em `WEB_PANEL_PORT`).

### Painel

- `/logs` &ndash; exibe os registros em tempo real usando Server-Sent Events.
- `/blocked` &ndash; mostra os IPs bloqueados e sincroniza a lista com o UFW.
- `/log/<id>` &ndash; página individual com detalhes completos do log.

### Firewall

Quando uma requisição é classificada como perigosa ou excede o limiar de negação de serviço, o IP de origem é bloqueado no UFW **apenas para a porta configurada em `UNIT_BACKEND_PORT`** e gravado no banco (se configurado). Os dados também ficam salvos em arquivo no caminho definido por `LOG_FILE`.

### Configurações de bloqueio

Os limiares usados para bloquear IPs podem ser ajustados por variáveis de ambiente:

- `BLOCK_SEVERITY_LEVELS` &ndash; níveis de severidade que resultam em bloqueio imediato (padrão `error,high`).
- `BLOCK_ANOMALY_THRESHOLD` &ndash; probabilidade mínima de anomalia para bloquear quando o evento também é considerado *outlier* semântico (padrão `0.5`).

## Banco de dados

Defina `POSTGRES_HOST` e as demais variáveis de conexão para ativar o uso de PostgreSQL. Caso contrário, o proxy funciona sem dependência de banco, apenas registrando em arquivo.

## Pentest e testes

A pasta `pentest` inclui scripts de verificação e testes de ataque:

```bash
python pentest/test_structure.py   # valida a estrutura do projeto
python pentest/test_security.py    # envia uma requisição suspeita e consulta os logs
python pentest/test_attacks.py     # executa vários vetores de ataque contra o proxy
```

Execute os testes de segurança com o proxy e o painel ativos.

A detecção de ameaças também integra-se ao firewall **UFW**. Sempre que um ataque ou invasão é identificado, o IP de origem é automaticamente bloqueado via UFW e registrado no banco de dados.
O painel web possui a página `http://localhost:8080/blocked` que exibe todos os IPs bloqueados, seu status, motivo e data/hora do bloqueio.
Sempre que essa página é acessada, a lista é sincronizada com as regras atuais do UFW, garantindo que o banco reflita o estado real do firewall.
O proxy também monitora a quantidade de requisições de cada IP e bloqueia automaticamente padrões que indiquem ataques de negação de serviço.

### Whitelist

IPs que nunca devem ser bloqueados podem ser cadastrados em uma whitelist. Os endereços
ficam armazenados no banco de dados e podem ser gerenciados pelo menu interativo do
proxy. Utilize a nova opção **Gerenciar Whitelist** para listar, adicionar ou remover IPs.