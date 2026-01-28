import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Shield } from 'lucide-react'
import { motion } from 'framer-motion'
import Button from '../components/ui/Button'
import Input from '../components/ui/Input'
import Modal from '../components/ui/Modal'
import { authAPI } from '../api/client'
import { useAuthStore } from '../store/authStore'

export default function LoginPage() {
    const navigate = useNavigate()
    const { setUser, setRequires2FA, requires2FA, tempCredentials } = useAuthStore()

    const [isRegister, setIsRegister] = useState(false)
    const [isLoading, setIsLoading] = useState(false)
    const [error, setError] = useState('')

    // Form state
    const [email, setEmail] = useState('')
    const [password, setPassword] = useState('')
    const [twoFACode, setTwoFACode] = useState('')

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault()
        setError('')
        setIsLoading(true)

        try {
            if (isRegister) {
                const response = await authAPI.register({ email, password })
                if (response.success) {
                    alert('Usuário registrado com sucesso! Faça login.')
                    setIsRegister(false)
                    setPassword('')
                } else {
                    setError(response.msg || response.message || 'Erro no registro')
                }
            } else {
                const response = await authAPI.login({ email, password })

                if (response.requires_mfa || response.requires_2fa) {
                    setRequires2FA(true, email)
                } else if (response.success && response.email && response.access_token) {
                    setUser({
                        email: response.email,
                        has_2fa: response.has_2fa || false,
                    }, response.access_token)
                    navigate('/')
                } else {
                    setError(response.msg || response.message || 'Credenciais inválidas')
                }
            }
        } catch (err: any) {
            setError(err.message || 'Erro de conexão')
        } finally {
            setIsLoading(false)
        }
    }

    const handleVerify2FA = async (e: React.FormEvent) => {
        e.preventDefault()
        setError('')
        setIsLoading(true)

        try {
            // Using loginMFA because this is the Login flow
            const response = await authAPI.loginMFA({
                code: twoFACode
            })

            if (response.success && response.access_token) {
                // Get status to get user info if needed, or use response
                setUser({
                    email: response.email || tempCredentials?.email || '',
                    has_2fa: true,
                }, response.access_token)
                navigate('/')
            } else {
                setError(response.msg || 'Código 2FA inválido')
            }
        } catch (err: any) {
            setError(err.message || 'Erro na verificação 2FA')
        } finally {
            setIsLoading(false)
        }
    }

    return (
        <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-primary/10 via-white dark:from-dark-950 dark:via-dark-900 to-secondary/10 dark:to-dark-950 p-4">
            <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.4 }}
                className="w-full max-w-md"
            >
                <div className="bg-white dark:bg-dark-800 rounded-2xl shadow-2xl p-8">
                    {/* Logo */}
                    <div className="flex justify-center mb-8">
                        <div className="p-4 bg-primary/10 rounded-2xl">
                            <Shield className="w-16 h-16 text-primary" />
                        </div>
                    </div>

                    {/* Title */}
                    <div className="text-center mb-8">
                        <h1 className="text-3xl font-bold text-gray-900 dark:text-white mb-2">
                            Camellia Shield
                        </h1>
                        <p className="text-gray-600 dark:text-gray-400">
                            Criptografia de nível militar
                        </p>
                    </div>

                    {/* Error */}
                    {error && (
                        <div className="mb-4 p-3 bg-danger/10 border border-danger/20 text-danger rounded-lg text-sm">
                            {error}
                        </div>
                    )}

                    {/* Form */}
                    <form onSubmit={handleSubmit} className="space-y-4">
                        <Input
                            label="Email"
                            type="email"
                            value={email}
                            onChange={(e) => setEmail(e.target.value)}
                            placeholder="seu@email.com"
                            required
                        />

                        <Input
                            label="Senha"
                            type="password"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            placeholder="••••••••"
                            required
                        />

                        <Button
                            type="submit"
                            className="w-full"
                            isLoading={isLoading}
                        >
                            {isRegister ? 'Registrar' : 'Entrar'}
                        </Button>
                    </form>

                    {/* Toggle */}
                    <div className="mt-6 text-center">
                        <button
                            type="button"
                            onClick={() => {
                                setIsRegister(!isRegister)
                                setError('')
                            }}
                            className="text-sm text-primary hover:underline"
                        >
                            {isRegister
                                ? 'Já tem conta? Faça login'
                                : 'Não tem conta? Registre-se'}
                        </button>
                    </div>
                </div>
            </motion.div>

            {/* 2FA Modal */}
            <Modal
                isOpen={requires2FA}
                onClose={() => setRequires2FA(false)}
                title="Verificação 2FA"
            >
                <form onSubmit={handleVerify2FA} className="space-y-4">
                    <p className="text-sm text-gray-600 dark:text-gray-400 mb-4">
                        Digite o código de 6 dígitos do seu autenticador:
                    </p>

                    <Input
                        label="Código 2FA"
                        type="text"
                        value={twoFACode}
                        onChange={(e) => setTwoFACode(e.target.value)}
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
                        Verificar
                    </Button>
                </form>
            </Modal>
        </div>
    )
}
