# Nginx Unit IA

Este projeto cria uma camada de proteção inteligente para o proxy [Nginx Unit](https://unit.nginx.org/) utilizando modelos de linguagem do HuggingFace. A aplicação roda em containers e analisa o tráfego em tempo real para detectar possíveis ataques (DoS, DDoS, etc.).

## Estrutura
- `docker-compose.yml` define dois serviços: o proxy Nginx Unit (onde sua aplicação pode ser executada) e o detector responsável pela proteção.
- `Dockerfile` constroi a imagem para a aplicação, baixando os modelos necessários.
- `app/` contém o código Python responsável pela detecção.
- `schema.sql` contém a estrutura do banco de dados.
- `.env.example` é um modelo de configuração (copie para `.env`). Inclui a variável `DEVICE` para definir se a inferência será feita em CPU ou GPU.

## Uso rápido
1. Copie `.env.example` para `.env` e ajuste as variáveis.
2. Execute `docker-compose up --build` para iniciar tudo.
3. Utilize o menu interativo para ativar ou desativar a proteção e selecionar a interface de rede.

A aplicação realiza análise semântica e detecção de anomalias nos logs. Caso variáveis de banco estejam configuradas, os resultados são armazenados no PostgreSQL informado.\
Um painel web simples está disponível em `http://localhost:8080/logs` para visualizar os logs registrados.
