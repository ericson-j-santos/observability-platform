# Observability Platform

Plataforma reutilizável de observabilidade para aplicações e serviços, iniciada a partir das capacidades já existentes no ReqSys.

## Responsabilidade

Este repositório é proprietário da infraestrutura e dos contratos transversais de:

- logs estruturados;
- redaction de segredos e dados pessoais;
- correlação por `correlation_id`, `request_id`, `trace_id` e `span_id`;
- OpenTelemetry Collector;
- coleta e transporte de logs, métricas e traces;
- armazenamento técnico de telemetria;
- Prometheus, Grafana e Alertmanager;
- retenção técnica;
- dashboards, alertas, testes de contrato e runbooks.

## Fora do escopo

Regras funcionais e dados de auditoria pertencem aos produtos consumidores. No ReqSys, por exemplo, `auditoria_eventos` continua sendo responsabilidade do próprio ReqSys.

## Princípios

1. contrato versionado;
2. nenhuma credencial versionada;
3. redaction antes de persistência;
4. baixa cardinalidade em métricas;
5. correlação ponta a ponta;
6. separação DEV/STG/PROD;
7. fail-closed para configuração insegura;
8. evidência vinculada ao SHA e ao `correlation_id`;
9. runtime preferencial sem custo adicional quando tecnicamente compatível.

## Primeiro consumidor

`ericson-j-santos/reqsys-v2-enterprise-real`.

## Estado

Baseline DEV funcional versionado para logs, métricas e traces. O incremento de Alertmanager DEV é validado por CI/E2E antes de ser incorporado à `main`; STG/PROD permanecem fora do escopo.
