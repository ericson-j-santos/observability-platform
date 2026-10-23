# Failure intelligence

## Objetivo

Transformar falhas e logs em um ciclo de melhoria contínua, sem confundir cascatas,
cancelamentos ou ruído operacional com causas-raiz independentes.

\`\`\`text
coleta -> sanitização -> normalização -> fingerprint -> classificação
       -> Pareto -> backlog -> correção -> regressão -> verificação de reincidência
\`\`\`

## Contrato

A saída usa \`observability.failure-analysis/v1\` e separa:

- \`root_cause_groups\`: candidatos reais a correção;
- \`cascade_groups\`: gates/workflows que falharam porque uma dependência upstream falhou;
- \`noise_groups\`: cancelamentos e sinais que devem ser tratados como saúde do fluxo;
- \`pareto\`: até dez causas-raiz ordenadas por score reproduzível.

O score é intencionalmente simples e auditável:

\`ocorrências × quantidade de workflows afetados × peso da categoria\`.

Ele prioriza frequência e blast radius sem fingir precisão estatística.

## Segurança

O coletor não publica logs brutos. Ele mantém somente linhas diagnósticas,
e o analisador aplica a redaction canônica antes de gerar amostras e assinaturas.
O arquivo temporário de coleta deve permanecer no \`RUNNER_TEMP\`; publique somente
o relatório sanitizado.

## Uso como ação reutilizável

Depois que um SHA do \`observability-platform\` estiver integrado e validado, um
repositório consumidor pode fixar esse SHA:

\`\`\`yaml
permissions:
  contents: read
  actions: read

steps:
  - uses: ericson-j-santos/observability-platform/.github/actions/failure-analysis@<SHA_IMUTAVEL>
    id: failure_analysis
    with:
      github-token: \${{ github.token }}
      max-runs: "100"
      max-failed-jobs: "40"
      since-hours: "24"
\`\`\`

O consumidor decide como persistir ou projetar o JSON. A análise não deve abrir,
fechar ou corrigir issues automaticamente apenas pelo score. A automação de
correção deve continuar sujeita aos gates do projeto e a evidência de causa-raiz.

## Fluxo recomendado para todos os projetos

1. Executar após falha relevante e também em reconciliação de baixa frequência.
2. Ignorar \`cascade_groups\` como backlog independente.
3. Tratar concentração de \`noise_groups\` como problema de orquestração/concurrency.
4. Para o primeiro item do Pareto, reproduzir a falha e corrigir a causa-raiz.
5. Adicionar teste de regressão que falhe no comportamento anterior.
6. Reexecutar o fluxo funcional/E2E no SHA corrigido.
7. Confirmar na janela seguinte que o fingerprint deixou de reincidir.
8. Só então avançar para a próxima causa do Pareto.

## Limites

- O classificador é determinístico e baseado em evidências textuais sanitizadas;
  ele não substitui diagnóstico humano quando a origem não expõe causa suficiente.
- \`unclassified_failure\` é um sinal de que a observabilidade do produtor precisa
  melhorar, não uma licença para adivinhar a causa.
- Cancelamento não é considerado falha funcional por padrão.
- Custo adicional desconhecido permanece bloqueado.
