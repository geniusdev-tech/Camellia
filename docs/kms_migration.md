# Playbook: Provisionamento de KMS (AWS KMS) e migração de chaves

Este documento descreve passos recomendados para provisionar um KMS (ex.: AWS KMS) e migrar material de chave do `FileKMS` local para KMS gerenciado.

Pré-requisitos
- Conta AWS com permissões para `kms:GenerateDataKey`, `kms:Decrypt`, `kms:CreateKey`, `kms:ScheduleKeyDeletion`.
- `aws` CLI configurada localmente (`aws configure`) ou credenciais em GitHub Secrets para CI.

Passos recomendados
1. Criar a chave mestra (CMK)
   - AWS Console → KMS → Create key → Symmetric
   - Anotar o KeyId/ARN (ex: `arn:aws:kms:us-east-1:123456789012:key/abcd-...`)

2. Testar geração de data key localmente
   - Usar o snippet em `core/kms/aws_kms.py` (método `generate_data_key`) ou o AWS CLI:

```bash
aws kms generate-data-key --key-id <KEY_ID> --key-spec AES_256 --query CiphertextBlob --output text | base64 --decode > dek.cipher
```

3. Exportar/backup da chave mestra local (se aplicável)
   - Se você está usando `FileKMS` com uma chave de envelope, faça backup do arquivo de master key antes de rotacionar.

4. Migrar existentes vaults/artefatos
   - Para cada vault/manifest que tenha `encrypted_dek` vazio (ou que armazene DEK localmente):
     - Decrypt o DEK com `FileKMS.decrypt_data_key` localmente
     - Chamar `GenerateDataKey` no KMS novo para obter `CiphertextBlob` e `Plaintext`
     - Re-encrypt o DEK: armazenar o `CiphertextBlob` (base64) no campo `encrypted_dek` do manifest e descartar o plaintext em RAM assim que possível
   - Atualizar manifests e verificar assinaturas/consistência

5. Atualizar configurações de ambiente
   - Definir `KMS_PROVIDER=aws`
   - Definir `AWS_KMS_KEY_ID` (o KeyId ou ARN) e garantir credentials no ambiente de execução (CI/hosts)

6. Testar leitura/escrita em staging
   - Validar que `VaultManager` consegue descriptografar usando `AWSKMSProvider.decrypt_data_key`
   - Executar `pytest` e ver logs de integração

7. Rotacionar / remover o `FileKMS`
   - Após validar, agende remoção do `FileKMS` e delete chaves locais seguras (apagar backups, secure wipe)

Notas de segurança
- Nunca persista plaintext de chaves em disco.
- Limite permissões KMS ao conjunto mínimo de identidades/roles.
- Considere uso de HSM em providers que suportam BYOK/CloudHSM para requisitos regulatórios.
