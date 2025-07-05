# Nginx Unit IA

Este projeto adiciona uma camada de segurança ao [Nginx Unit](https://unit.nginx.org/) utilizando modelos de linguagem do HuggingFace. Todas as requisições passam por um proxy em Python que analisa e classifica o conteúdo antes de encaminhar ao Nginx Unit. Logs e IPs suspeitos podem ser armazenados em PostgreSQL e consultados por um painel web.

## Funcionalidades

- Classifica severidade, anomalias e categorias de rede (NIDS) de cada requisição.
- Detecção semântica de comportamentos fora do padrão através de embeddings.
- Bloqueio automático de IPs suspeitos com integração ao firewall **UFW**.
- Painel web em Flask/Bootstrap com logs em tempo real e lista de IPs bloqueados.
- Registro opcional em banco PostgreSQL com esquema definido em `schema.sql`.
- Script interativo (`python -m app.menu`) para iniciar/parar o proxy e o painel, além de selecionar CPU ou GPU para inferência.

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

O proxy escutará na porta configurada em `UNIT_PORT` e encaminhará as requisições para `BACKEND_URL`. O painel estará disponível em `http://localhost:8080` (ou porta definida em `WEB_PANEL_PORT`).

### Painel

- `/logs` &ndash; exibe os registros em tempo real usando Server-Sent Events.
- `/blocked` &ndash; mostra os IPs bloqueados e sincroniza a lista com o UFW.

### Firewall

Quando uma requisição é classificada como perigosa ou excede o limiar de negação de serviço, o IP de origem é bloqueado no UFW e gravado no banco (se configurado). Os dados também ficam salvos em arquivo no caminho definido por `LOG_FILE`.

## Banco de dados

Defina `POSTGRES_HOST` e as demais variáveis de conexão para ativar o uso de PostgreSQL. Caso contrário, o proxy funciona sem dependência de banco, apenas registrando em arquivo.

## Pentest e testes

A pasta `pentest` inclui scripts de verificação:

```bash
python pentest/test_structure.py   # valida a estrutura do projeto
python pentest/test_security.py    # envia uma requisição suspeita e consulta os logs
```

Execute o segundo teste com o proxy e o painel ativos.

