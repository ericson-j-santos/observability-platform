# Arquitetura inicial

## Fluxo

Aplicação consumidora -> OTLP/HTTP ou OTLP/gRPC -> OpenTelemetry Collector.

No baseline DEV:

- logs são enviados ao Loki e a uma evidência local independente;
- métricas são expostas pelo Collector e coletadas pelo Prometheus;
- traces são recebidos pelo Collector e registrados na evidência local;
- Grafana consulta Loki e Prometheus.
- Prometheus avalia regras de disponibilidade e envia alertas ao Alertmanager local.

## Contrato de aplicação

Aplicações devem produzir eventos compatíveis com `contracts/observability-event.schema.json`.

Campos de correlação obrigatórios:

- `correlation_id`;
- `service_name`;
- `environment`;
- `event_name`;
- severidade;
- timestamp.

`request_id`, `trace_id` e `span_id` são opcionais no contrato base, mas devem ser propagados quando existirem.

## Segurança

Redaction ocorre antes do transporte. O baseline proíbe serializar `str(exception)` por padrão e disponibiliza `safe_error()`, que expõe somente o tipo da exceção.

Não versionar tokens, senhas, cookies, connection strings ou dados pessoais.

## Retenção DEV

- Loki: 7 dias;
- Prometheus: 7 dias.

STG/PROD exigem política específica e evidência antes de promoção.

## E2E

`scripts/e2e_dev.py`:

1. gera `correlation_id` exclusivo;
2. cria evento contendo segredo sintético;
3. comprova redaction antes do transporte;
4. envia log, métrica e trace ao Collector;
5. comprova os três sinais no exporter de evidência;
6. consulta o log no Loki pelo `correlation_id`;
7. comprova que o segredo não aparece no armazenamento.


## Alertas DEV

O baseline DEV inclui Alertmanager sem integração externa. A regra
`ObservabilityCollectorUnavailable` dispara quando o alvo Prometheus do Collector
fica indisponível e resolve após a recuperação do scrape.

O E2E `scripts/e2e_alert_lifecycle.py` comprova controle inicial sem alerta,
interrupção controlada apenas do Collector, estado `firing`, recuperação do alvo
e ausência de alerta ativo após resolução. O script restaura o Collector em
`finally` para falhar fechado sem deixar o runtime degradado.

Nenhum receiver externo é configurado neste baseline. Integrações com e-mail,
Teams, Slack, PagerDuty ou outros destinos exigem contrato, segredo e autorização
separados.
