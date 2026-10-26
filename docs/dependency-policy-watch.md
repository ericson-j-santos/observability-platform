# Dependency Policy Watch — GitHub Actions

## Objetivo e fronteiras

Verificar somente leitura nos repositórios públicos:

- `ericson-j-santos/desktop-pc24x7-runtime`
- `ericson-j-santos/engineering-worker-pool`

O workflow é executado em `ericson-j-santos/observability-platform`, usando `ubuntu-latest` público, biblioteca padrão Python e API oficial do GitHub. Não instala Docker, Podman nem Kubernetes, não executa código dos repositórios-alvo e não chama APIs pagas. Runners grandes, segredos adicionais, Docker, serviços pagos, merges, deployments, exclusões e alterações nos repositórios fiscalizados não fazem parte do fluxo.

## Alertas

Diariamente às 12:00 UTC (~09:00 São Paulo, sem garantia de horário exato do agendamento do GitHub), o monitor:

1. lê o checkpoint na issue técnica de controle, exclusivamente no repositório `observability-platform`;
2. compara o `main` de cada alvo com o SHA confirmado no último checkpoint. O primeiro ciclo usa a `main` corrente como baseline, sem extrapolar mudanças anteriores;
3. lê as PRs abertas e compara cada SHA com o último inspecionado, incluindo PRs existentes na primeira execução;
4. inspeciona somente linhas **adicionadas** nos diffs; remoções, docs, arquivos binários e fixtures não geram achado;
5. classifica `COMPROVADA` a introdução estática de instruções/manifests/pacotes Docker, Podman ou Kubernetes, e `SUSPEITA` o possível custo extra de larger runners, tiers pagos, provisionamento cloud ou deploy externo;
6. emite **uma issue por alteração nova** no repositório de controle e atribui ao proprietário, com PR ou commit, SHA, arquivo/linha, URL de evidência, impacto, risco e menor correção segura;
7. suprime alertas repetidos pelo fingerprint `repositório + arquivo + tecnologia + linha adicionada` e confirma o checkpoint por leitura independente.

Um `COMPROVADA` refere-se à **introdução de dependência no código**: não prova execução em host ou despesa financeira efetiva. A etiqueta `SUSPEITA` nunca é representada como cobrança real. A issue técnica de checkpoint (`[monitor-state]`) **não é um alerta** e não possui atribuição.

## Fail-closed e privacidade

- Quando API falha, SHA diverge, diff some ou paginação fica incompleta, a execução falha sem avançar checkpoint nem declarar conformidade.
- O monitor só escreve issues no repositório de controle; mesmo com credenciais, POST/PATCH contra um alvo é rejeitado.
- Logs e alertas armazenam só trechos sanitizados e links públicos; não gravam credenciais nem dumps de conteúdo.
- Não há dependência de artefatos/cache/custos de armazenamento do GitHub Actions.
- O escopo de permissões `issues: write` é exclusivo do job agendado na `main`. PRs executam somente testes e consulta read-only.
- O detector é deliberadamente de alta precisão: linhas de documentação e referências indiretas podem não gerar alertas. Um diff com sinal não reconhecido não equivale a garantia de conformidade universal.
- GitHub Actions `schedule` pode sofrer atraso ou interrupção. A execução depois do atraso compara o SHA persistido, sem depender de janela fixa de 24h. GitHub Compare tem limite de 250 commits e 300 arquivos; exceder o limite bloqueia o ciclo até reconciliação segura.
- A issue de checkpoint preserva SHA de main e PRs abertas, **não altera** os repositórios monitorados.

## Validação e aceite

Pré-merge: syntax check, testes positivos, negativos, idempotência, teste de erro de API e controle de autorização; PR CI com consulta read-only real dos dois alvos. O CI existente em `observability-platform` também deve passar no HEAD atual. Após merge autorizado, a validação operacional exige uma execução do workflow na `main` com readback do checkpoint e confirmação de emissão/supressão de alerta apenas diante de alteração real. A notificação do GitHub depende das configurações de notificações do usuário; criar/atribuir uma issue não prova entrega por e-mail ou push.

**Não integrar automaticamente**: a branch e PR são preparadas para revisão. Até a integração, não há agendamento ativo do novo monitor.
