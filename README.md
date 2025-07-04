# Nginx Unit IA

Este projeto cria uma camada de proteção inteligente para o proxy [Nginx Unit](https://unit.nginx.org/) utilizando modelos de linguagem do HuggingFace. A aplicação executa dentro de um `docker-compose` junto a um banco PostgreSQL e analisa os logs em tempo real para detectar possíveis ataques (DoS, DDoS, etc.).

## Estrutura
- `docker-compose.yml` define os serviços: PostgreSQL, Nginx Unit e a aplicação Python.
- `Dockerfile` constroi a imagem para a aplicação, baixando os modelos necessários.
- `app/` contém o código Python responsável pela detecção.
- `schema.sql` contém a estrutura do banco de dados.
- `.env.example` é um modelo de configuração (copie para `.env`).

## Uso rápido
1. Copie `.env.example` para `.env` e ajuste as variáveis.
2. Execute `docker-compose up --build` para iniciar tudo.
3. Utilize o menu interativo para ativar ou desativar a proteção e selecionar a interface de rede.

A aplicação realiza análise semântica e detecção de anomalias nos logs, registrando os resultados no banco.
