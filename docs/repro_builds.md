# Builds Reproducíveis e Assinatura de Releases

1. Use ambientes controlados (build containers) com versões fixas de ferramentas.
2. Gere artefatos (wheel / tar.gz) e assine com GPG: `gpg --detach-sign --armor dist/package.whl`
3. Publique checksums assinados (SHA256) e verifique assinaturas para distribuição.
4. Armazene chaves de assinatura em HSM/KMS para produção.
