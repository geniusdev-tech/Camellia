import { useState } from 'react'
import { Shield } from 'lucide-react'
import Button from '../components/ui/Button'
import Modal from '../components/ui/Modal'
import Input from '../components/ui/Input'
import { authAPI } from '../api/client'
import { useAuthStore } from '../store/authStore'

export default function SettingsPage() {
    const { user, setUser, accessToken } = useAuthStore()
    const [show2FASetup, setShow2FASetup] = useState(false)
    const [qrCode, setQrCode] = useState('')
    const [secret, setSecret] = useState('')
    const [verifyCode, setVerifyCode] = useState('')
    const [isLoading, setIsLoading] = useState(false)
    const [error, setError] = useState('')

    const handleSetup2FA = async () => {
        setIsLoading(true)
        setError('')

        try {
            const response = await authAPI.setup2FA()
            if (response.success) {
                setQrCode(response.qr_code)
                setSecret(response.secret)
                setShow2FASetup(true)
            } else {
                setError(response.msg || 'Erro ao configurar 2FA')
            }
        } catch (err: any) {
            setError(err.message || 'Erro ao configurar 2FA')
        } finally {
            setIsLoading(false)
        }
    }

    const handleConfirm2FA = async (e: React.FormEvent) => {
        e.preventDefault()
        setIsLoading(true)
        setError('')

        try {
            const response = await authAPI.confirm2FA(secret, verifyCode)
            if (response.success) {
                if (user && accessToken) {
                    setUser({ ...user, has_2fa: true }, accessToken)
                }
                setShow2FASetup(false)
                alert('2FA ativado com sucesso!')
                setVerifyCode('')
            } else {
                setError(response.msg || 'Código inválido')
            }
        } catch (err: any) {
            setError(err.message || 'Erro na verificação')
        } finally {
            setIsLoading(false)
        }
    }

    const handleDisable2FA = async () => {
        if (!confirm('Tem certeza que deseja desativar o 2FA? Isso reduzirá sua segurança.')) {
            return
        }

        setIsLoading(true)
        try {
            const response = await authAPI.disable2FA()
            if (response.success) {
                if (user && accessToken) {
                    setUser({ ...user, has_2fa: false }, accessToken)
                }
                alert('2FA desativado')
            }
        } catch (err) {
            console.error('Disable 2FA error:', err)
        } finally {
            setIsLoading(false)
        }
    }

    return (
        <div className="max-w-2xl mx-auto">
            <div className="bg-white dark:bg-dark-800 rounded-xl shadow-lg p-6">
                <div className="flex items-center gap-3 mb-6">
                    <Shield className="w-6 h-6 text-primary" />
                    <h2 className="text-2xl font-bold text-gray-900 dark:text-white">
                        Configurações de Segurança
                    </h2>
                </div>

                {/* 2FA Section */}
                <div className="border-t dark:border-dark-700 pt-6">
                    <div className="flex items-start justify-between">
                        <div>
                            <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">
                                Autenticação de Dois Fatores (2FA)
                            </h3>
                            <p className="text-sm text-gray-600 dark:text-gray-400">
                                Adicione uma camada extra de segurança à sua conta
                            </p>
                            {user?.has_2fa && (
                                <div className="mt-2 inline-flex items-center gap-2 px-3 py-1 bg-secondary/10 text-secondary rounded-full text-sm">
                                    ✓ 2FA Ativo
                                </div>
                            )}
                        </div>

                        <div>
                            {user?.has_2fa ? (
                                <Button
                                    variant="danger"
                                    onClick={handleDisable2FA}
                                    isLoading={isLoading}
                                >
                                    Desativar 2FA
                                </Button>
                            ) : (
                                <Button
                                    onClick={handleSetup2FA}
                                    isLoading={isLoading}
                                >
                                    Ativar 2FA
                                </Button>
                            )}
                        </div>
                    </div>
                </div>

                {/* Auto-Lock Configuration */}
                <div className="border-t dark:border-dark-700 pt-6 mt-6">
                    <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
                        Behavior & Session
                    </h3>

                    <div className="grid gap-6">
                        <div className="flex items-center justify-between">
                            <div>
                                <h4 className="font-medium text-gray-900 dark:text-white">Auto-Lock Timer</h4>
                                <p className="text-sm text-gray-500">Bloquear cofre após inatividade</p>
                            </div>
                            <select className="bg-gray-50 dark:bg-dark-900 border border-gray-200 dark:border-dark-700 rounded-lg px-3 py-2 text-sm">
                                <option value="5">5 minutos</option>
                                <option value="15">15 minutos</option>
                                <option value="30">30 minutos</option>
                                <option value="0">Nunca (Inseguro)</option>
                            </select>
                        </div>

                        <div className="flex items-center justify-between">
                            <div>
                                <h4 className="font-medium text-gray-900 dark:text-white">Nível de Inspeção (DII)</h4>
                                <p className="text-sm text-gray-500">Intensidade da verificação de arquivos</p>
                            </div>
                            <select className="bg-gray-50 dark:bg-dark-900 border border-gray-200 dark:border-dark-700 rounded-lg px-3 py-2 text-sm">
                                <option value="basic">Padrão (Hash + Ext)</option>
                                <option value="paranoid">Paranoid (Entropia + Deep Scan)</option>
                            </select>
                        </div>
                    </div>
                </div>

                {/* Panic Zone */}
                <div className="border-t border-danger/20 bg-danger/5 rounded-xl p-6 mt-8">
                    <h3 className="text-lg font-bold text-danger mb-2 flex items-center gap-2">
                        🛑 DANGER ZONE
                    </h3>
                    <p className="text-sm text-gray-600 dark:text-gray-400 mb-6">
                        Ações críticas de emergência. Use com extrema cautela.
                    </p>

                    <div className="flex items-center justify-between">
                        <div>
                            <h4 className="font-bold text-gray-900 dark:text-white">Panic Wipe</h4>
                            <p className="text-sm text-gray-500">Encerra sessão e limpa chaves da memória RAM imediatamente.</p>
                        </div>
                        <Button
                            variant="danger"
                            onClick={() => {
                                if (confirm('EMERGÊNCIA: Isso fechará sua sessão imediatamente. Confirmar?')) {
                                    authAPI.logout().then(() => window.location.href = '/login')
                                }
                            }}
                        >
                            EXECUTAR WIPE
                        </Button>
                    </div>
                </div>
            </div>

            {/* 2FA Setup Modal */}
            <Modal
                isOpen={show2FASetup}
                onClose={() => setShow2FASetup(false)}
                title="Configurar 2FA"
                size="md"
            >
                <div className="space-y-4">
                    <div className="text-center">
                        <p className="text-sm text-gray-600 dark:text-gray-400 mb-4">
                            Escaneie o QR Code com seu aplicativo autenticador:
                        </p>

                        {qrCode && (
                            <div className="flex justify-center mb-4">
                                <img
                                    src={qrCode}
                                    alt="QR Code 2FA"
                                    className="w-48 h-48 bg-white p-2 rounded-lg"
                                />
                            </div>
                        )}

                        {secret && (
                            <div className="mb-4 p-3 bg-gray-100 dark:bg-dark-700 rounded-lg">
                                <p className="text-xs text-gray-600 dark:text-gray-400 mb-1">
                                    Ou digite manualmente:
                                </p>
                                <code className="text-sm font-mono">{secret}</code>
                            </div>
                        )}
                    </div>

                    {error && (
                        <div className="p-3 bg-danger/10 border border-danger/20 text-danger rounded-lg text-sm">
                            {error}
                        </div>
                    )}

                    <form onSubmit={handleConfirm2FA} className="space-y-4">
                        <Input
                            label="Digite o código para confirmar"
                            type="text"
                            value={verifyCode}
                            onChange={(e) => setVerifyCode(e.target.value)}
                            placeholder="000000"
                            maxLength={6}
                            required
                            className="text-center text-2xl tracking-widest"
                        />

                        <Button
                            type="submit"
                            className="w-full"
                            isLoading={isLoading}
                        >
                            Confirmar e Ativar
                        </Button>
                    </form>
                </div>
            </Modal>
        </div>
    )
}
