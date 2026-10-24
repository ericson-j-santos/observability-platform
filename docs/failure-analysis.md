# Failure intelligence

## Objetivo

Transformar execuções e logs de CI em um ciclo reproduzível de melhoria contínua,
sem multiplicar a mesma causa por cascatas, controles ou cancelamentos esperados.

```text
coleta paginada -> sanitização -> normalização -> fingerprint -> classificação
                -> estado ativo/recuperado -> Pareto -> backlog acionável
                -> correção -> regressão -> E2E -> verificação de reincidência
```

O fluxo usa somente Python da biblioteca padrão e a API nativa do GitHub. Ele não
exige banco, serviço permanente nem runtime Docker.

## Contratos

A coleta usa `observability.failure-collection/v1` e registra:

- repositório e janela temporal;
- execuções consultadas e execuções dentro da janela;
- totais de sucesso, falha, timeout, ação requerida e cancelamento;
- quantidade de logs de jobs efetivamente lidos;
- `truncated=true` quando o limite de runs termina antes da janela;
- sinais mínimos e sanitizáveis usados pela análise.

O relatório usa `observability.failure-analysis/v2`. As chaves históricas
`root_cause_groups`, `control_groups`, `cascade_groups`,
`noise_groups` e `pareto` continuam disponíveis. A v2 acrescenta:

- `collection` e `summary` para evidência da janela;
- classificação exclusiva `root_cause | control | cascade | noise`;
- `active_root_cause_groups` e `recovered_root_cause_groups`;
- `unverified_cancellation_groups`;
- componentes auditáveis de frequência e impacto;
- `actionable_backlog` com evidência, recomendação e critérios de aceite.

## Classificação operacional

- `root_cause`: defeito ou condição técnica corrigível. Só entra no Pareto
  enquanto houver incidente sem recuperação comprovada.
- `control`: bloqueio esperado, como custo desconhecido, autorização humana
  ausente ou limite de coleta. Não vira bug e não autoriza contorno.
- `cascade`: efeito downstream de erro upstream. Não abre item independente.
- `noise`: cancelamento com sucessor temporalmente correlacionado no mesmo
  workflow, tipo de evento e escopo de PR/branch.

Cancelamento sem sucessor comprovado permanece na categoria
`unverified_cancellation`, visível em `cascade_groups` e também na
lista dedicada. Ele nunca é descartado silenciosamente.

## Atividade e recuperação

Para cada falha, o coletor procura uma execução posterior bem-sucedida do mesmo
workflow, do mesmo tipo de evento e do mesmo escopo:

1. mesmo PR, quando há PR;
2. mesma branch, inclusive quando o SHA mudou;
3. mesmo SHA, quando PR e branch não estão disponíveis.

Um grupo só recebe `status=recovered` quando todos os seus incidentes lógicos
possuem sucessor bem-sucedido observado. Causas recuperadas continuam no relatório
histórico, mas saem do Pareto e do backlog ativo. Ausência de evidência de recuperação
mantém o grupo ativo; não se presume sucesso.

## Deduplicação

Em eventos ligados à mesma mudança (`push`, PR e merge group), o mesmo
repositório + SHA + fingerprint conta como um incidente lógico. Execuções agendadas
ou manuais distintas continuam separadas, mesmo no mesmo SHA, para preservar a
reincidência real.

## Pareto por frequência e impacto

O cálculo é simples e reproduzível:

```text
frequency_score = incidentes lógicos
impact_score    = peso da severidade x repositórios afetados x workflows afetados
priority_score  = frequency_score x impact_score
```

A saída inclui contribuição acumulada e separa a faixa `top_80` da cauda
longa. Somente causas-raiz ativas participam do denominador.

## Backlog acionável

Cada item de `actionable_backlog` contém:

- ID estável derivado do fingerprint;
- prioridade Pareto, estado e score decomposto;
- runs, SHAs, janela e amostra sanitizada;
- ação recomendada;
- critérios de aceite para reprodução, correção da causa primária, teste de
  regressão, maior E2E autorizado e ausência de reincidência na janela seguinte.

`unclassified_failure` gera item `needs_observability`: primeiro o
produtor deve expor código/causa estável; a automação não adivinha a correção.

O arquivo Markdown é adequado para triagem humana. O JSON permanece a fonte
estruturada. O score não abre issue, faz merge, deploy, mudança administrativa ou
gasto automaticamente.

## Uso como ação reutilizável

Depois da integração e validação, fixe sempre um SHA imutável:

```yaml
permissions:
  contents: read
  actions: read

steps:
  - uses: ericson-j-santos/observability-platform/.github/actions/failure-analysis@<SHA_IMUTAVEL>
    id: failure_analysis
    with:
      github-token: ${{ github.token }}
      max-runs: "300"
      max-failed-jobs: "80"
      since-hours: "24"
      output-path: artifacts/failure-analysis/report.json
      backlog-path: artifacts/failure-analysis/backlog.md
```

Outputs disponíveis:

- `report-path`;
- `backlog-path`;
- `active-root-causes`;
- `actionable-backlog-items`;
- `top-fingerprint`.

A ação escreve o backlog sanitizado no Job Summary, mas o consumidor decide se e
como persiste os arquivos. Logs brutos e o token nunca são publicados.

## Execução reproduzível sem ação

```bash
export FAILURE_ANALYSIS_TOKEN="<token fornecido pelo ambiente>"
PYTHONPATH=src python scripts/github_actions_failure_collector.py \
  --repository owner/repo \
  --output /tmp/failure-collection.json \
  --max-runs 300 \
  --max-failed-jobs 80 \
  --since-hours 24 \
  --token-env FAILURE_ANALYSIS_TOKEN

PYTHONPATH=src python scripts/analyze_failures.py \
  --input /tmp/failure-collection.json \
  --output artifacts/failure-analysis/report.json \
  --backlog-output artifacts/failure-analysis/backlog.md
```

O token deve vir do ambiente e ter somente `actions:read`. Redirecionamentos
de logs são aceitos apenas por HTTPS para hosts allowlisted e nunca recebem o header
de autorização.

## Fluxo recorrente recomendado

1. Executar após falha relevante.
2. Usar reconciliação de baixa frequência apenas como rede de segurança.
3. Selecionar o primeiro item `top_80` do backlog.
4. Reproduzir e corrigir a causa primária.
5. Adicionar teste preventivo.
6. Executar o maior E2E autorizado no SHA corrigido.
7. Rodar novamente em uma janela posterior.
8. Encerrar o item somente quando o fingerprint não tiver incidente ativo.

Sem janela posterior, a correção é tecnicamente validada, mas a prevenção ainda
não está comprovada longitudinalmente.

## Migração da v1

Consumidores fixados no SHA da v1 não mudam. Ao adotar um SHA da v2:

- aceitar o novo `schema_version`;
- consumir `active_root_cause_groups` para backlog corrente;
- manter `root_cause_groups` apenas para histórico;
- usar `actionable_backlog` em vez de inferir tarefas do Pareto;
- aceitar o objeto de coleta; o analisador ainda lê arrays e JSONL legados.

## Limites e segurança

- o classificador é determinístico e depende de evidência textual sanitizada;
- recuperação observada prova um run posterior verde no mesmo escopo, não prova
  ausência absoluta de flakiness;
- `truncated=true` exige reduzir a janela ou aumentar o limite dentro da
  política de custo zero;
- custo adicional desconhecido permanece bloqueado;
- nenhum segredo, log bruto ou payload sensível deve ser persistido;
- o fluxo não requer Docker permanente, storage externo ou recurso pago.
