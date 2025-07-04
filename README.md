# Nginx Unit IA

Este projeto cria uma camada de proteção inteligente para o proxy [Nginx Unit](https://unit.nginx.org/) utilizando modelos de linguagem do HuggingFace. Somente o Nginx Unit roda em container; os mecanismos de detecção, categorização e classificação devem ser executados fora do container.

## Estrutura
- `docker-compose.yml` define apenas o serviço do proxy Nginx Unit. A aplicação de detecção deve ser executada fora dos containers.
- `Dockerfile` constroi a imagem para a aplicação, baixando os modelos necessários.
- `app/` contém o código Python responsável pela detecção.
- `schema.sql` contém a estrutura do banco de dados.
- `.env.example` é um modelo de configuração (copie para `.env`). Inclui a variável `DEVICE` que define o dispositivo padrão (CPU ou GPU).

## Uso rápido
1. Copie `.env.example` para `.env` e ajuste as variáveis.
2. Execute `docker-compose up -d` para subir apenas o Nginx Unit.
3. Em seguida, rode `python -m app.menu` fora dos containers para iniciar a proteção
   e o painel web. No menu é possível selecionar a interface de rede e o dispositivo
   de inferência.

A aplicação realiza análise semântica e detecção de anomalias nos logs. Caso variáveis de banco estejam configuradas, os resultados são armazenados no PostgreSQL informado.\
Um painel web dinâmico (iniciado opcionalmente pelo menu) fica disponível em `http://localhost:8080/logs` para visualizar os logs registrados. O painel utiliza **Bootstrap** para uma interface mais limpa e permite alternar entre os modos claro e escuro.
