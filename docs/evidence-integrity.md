# Integridade da evidência E2E

A evidência deve identificar o código realmente executado. Informar um SHA
válido por variável de ambiente não comprova que aquele commit foi testado.

## Garantias deste incremento

- O checkout de Pull Request usa explicitamente o SHA do HEAD da PR.
- Antes de executar telemetria ou interromper o Collector do ambiente de teste,
  o preflight compara o HEAD Git com o SHA esperado, a raiz Git com o diretório
  do projeto e o remoto origin com o repositório GitHub esperado.
- URLs de remoto com credenciais, query, fragmento ou outro host são recusadas
  sem imprimir seu conteúdo.
- Mudanças rastreadas, preparadas ou não para commit, bloqueiam a validação.
- A mesma leitura é repetida após o teste e antes de publicar o JSON.
- Cada tentativa invalida seu JSON anterior antes de validar a identidade.
  Erro inicial, falha do teste ou divergência final não reaproveitam um passed.
- O JSON é publicado por substituição atômica; temporários de escrita falha
  são removidos. O ciclo de alerta mantém a restauração do Collector em finally.
- Artefatos do CI têm retenção de um dia para reduzir ocupação. O run, o SHA e
  o resumo da validação devem permanecer registrados na PR/issue.

## Destino dos arquivos

Os dois entrypoints aceitam --output somente para arquivos JSON não rastreados
sob artifacts/e2e-platform/, relativos à raiz do repositório ou absolutos dentro
dessa árvore. Links simbólicos em qualquer componente são recusados, assim como
arquivos rastreados. A limpeza de evidência não pode remover código ou seguir
um link para outro diretório.

Saídas geradas não participam da verificação de alterações rastreadas. Portanto,
essa verificação comprova a identidade e integridade da árvore versionada; não
equivale a uma atestação de todo o sistema operacional ou das dependências.

## Prevenção e limites

Os testes do adaptador usam repositórios Git temporários reais e um produtor
de resultado sintético para controlar HEAD, remoto, alterações e falhas.
Esses casos comprovam o comportamento do adaptador e não substituem o E2E da
stack. O CI mantém os testes reais de telemetria e de ciclo de alerta.

A validação de CI não comprova operação permanente no PC24x7/Noteri, integração
contínua com tráfego ReqSys, recuperação após reinício físico ou uma migração
para runtime nativo. A proteção efetiva da main também permanece um requisito
de integração independente, acompanhado na issue #2.
