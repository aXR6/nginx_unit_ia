# Nginx Unit IA

Este projeto cria uma camada de proteção inteligente para o proxy [Nginx Unit](https://unit.nginx.org/) utilizando modelos de linguagem do HuggingFace. Todo o tráfego que chega ao Nginx Unit passa antes por um proxy em Python que classifica as requisições e registra as detecções.

## Estrutura
- `docker-compose.yml` define o serviço do proxy Nginx Unit e uma aplicação de teste "Hello World". O proxy de segurança executa fora dos containers.
- `Dockerfile` constroi a imagem para a aplicação, baixando os modelos necessários.
- `app/` contém o código Python responsável pela detecção.
- `schema.sql` contém a estrutura do banco de dados.
- `.env.example` é um modelo de configuração (copie para `.env`). Inclui `UNIT_PORT` para a porta do proxy de segurança e `BACKEND_URL` apontando para o serviço Nginx Unit.
- Caso o modelo de detecção de anomalias retorne rótulos genéricos (`LABEL_0`, `LABEL_1`), o código mapeia automaticamente esses valores para `normal` e `anomaly`.

## Uso rápido
1. Copie `.env.example` para `.env` e ajuste as variáveis.
2. Execute `docker-compose up -d` para subir o Nginx Unit e a aplicação de teste.
3. Rode `python -m app.menu` para iniciar o proxy de segurança e, opcionalmente, o painel web.
   O menu permite ativar ou desativar o proxy, iniciar o painel e escolher CPU ou GPU para inferência.

A aplicação realiza análise semântica e detecção de anomalias nos logs. Caso variáveis de banco estejam configuradas, os resultados são armazenados no PostgreSQL informado.\
Um painel web dinâmico (iniciado opcionalmente pelo menu) fica disponível em `http://localhost:8080/logs` para visualizar os logs registrados. O painel utiliza **Bootstrap** para uma interface mais limpa e permite alternar entre os modos claro e escuro.
Os registros de novos acessos são transmitidos em tempo real via Server-Sent Events, mantendo a página atualizada sem recarregamentos.

## Firewall e bloqueio de IPs

A detecção de ameaças também integra-se ao firewall **UFW**. Sempre que um ataque ou invasão é identificado, o IP de origem é automaticamente bloqueado via UFW e registrado no banco de dados.
O painel web possui a página `http://localhost:8080/blocked` que exibe todos os IPs bloqueados, seu status, motivo e data/hora do bloqueio.
Sempre que essa página é acessada, a lista é sincronizada com as regras atuais do UFW, garantindo que o banco reflita o estado real do firewall.
O proxy também monitora a quantidade de requisições de cada IP e bloqueia automaticamente padrões que indiquem ataques de negação de serviço.
