# Política e Plano de Resposta a Incidentes

Resumo: Este documento fornece um esqueleto para detecção, triagem e resposta a incidentes de segurança.

1. Detecção
   - Logs centralizados (SIEM) e alertas automatizados.
   - Monitoramento de integridade do manifesto e auditoria de logs.

2. Triagem
   - Classificar: Confidencialidade/Integridade/Disponibilidade impactadas.
   - Priorizar: alto (exfiltração, chave comprometida), médio, baixo.

3. Contenção
   - Rotacionar chaves comprometidas via KMS.
   - Isolar instâncias/serviços afetados.

4. Erradicação & Recuperação
   - Restauração a partir de backups cifrados verificados.
   - Revalidação de integridade e testes pós-restore.

5. Comunicação
   - Notificar stakeholders e, se necessário, órgãos reguladores.

6. Lessons Learned
   - Post-mortem com medidas preventivas e atualização de políticas.
