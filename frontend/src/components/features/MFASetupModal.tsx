'use client'
import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { QrCode, ShieldCheck, X, Loader2, AlertCircle } from 'lucide-react'
import { authAPI } from '@/lib/api'

interface Props {
  open: boolean
  onClose: () => void
  onSuccess: () => void
}

export function MFASetupModal({ open, onClose, onSuccess }: Props) {
  const [step, setStep]     = useState<'qr' | 'verify'>('qr')
  const [secret, setSecret] = useState('')
  const [qrCode, setQrCode] = useState('')
  const [code, setCode]     = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError]   = useState('')

  const handleOpen = async () => {
    setLoading(true); setError('')
    try {
      const res = await authAPI.setup2FA()
      if (res.success) { setSecret(res.secret); setQrCode(res.qr_code); setStep('qr') }
      else setError(res.msg || 'Erro')
    } catch { setError('Erro de rede') }
    finally { setLoading(false) }
  }

  // kick off when modal opens
  const [initiated, setInitiated] = useState(false)
  if (open && !initiated) { setInitiated(true); handleOpen() }
  if (!open && initiated)  setInitiated(false)

  const verify = async () => {
    setLoading(true); setError('')
    try {
      const res = await authAPI.confirm2FA(secret, code)
      if (res.success) onSuccess()
      else setError(res.msg || 'Código inválido')
    } catch { setError('Erro de rede') }
    finally { setLoading(false) }
  }

  return (
    <AnimatePresence>
      {open && (
        <motion.div
          initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
          className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4"
          onClick={onClose}
        >
          <motion.div
            initial={{ scale: 0.95, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} exit={{ scale: 0.95, opacity: 0 }}
            className="glass rounded-2xl p-6 w-full max-w-sm shadow-panel"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Header */}
            <div className="flex items-center justify-between mb-5">
              <div className="flex items-center gap-2">
                <QrCode className="w-5 h-5 text-accent" />
                <h2 className="text-base font-semibold text-white">Configurar 2FA</h2>
              </div>
              <button onClick={onClose} className="text-gray-500 hover:text-white transition-colors">
                <X className="w-5 h-5" />
              </button>
            </div>

            {error && (
              <div className="flex items-center gap-2 p-3 mb-4 bg-danger/10 border border-danger/20 rounded-xl text-sm text-danger">
                <AlertCircle className="w-4 h-4 shrink-0" /> {error}
              </div>
            )}

            {loading && !qrCode ? (
              <div className="flex flex-col items-center py-10 gap-3">
                <Loader2 className="w-8 h-8 text-accent animate-spin" />
                <p className="text-sm text-gray-500">Gerando segredo…</p>
              </div>
            ) : step === 'qr' ? (
              <>
                <p className="text-xs text-gray-400 mb-4 text-center">
                  Escaneie o QR Code com Google Authenticator, Authy ou similar:
                </p>
                {qrCode && (
                  <div className="flex justify-center mb-4">
                    {/* eslint-disable-next-line @next/next/no-img-element */}
                    <img src={qrCode} alt="QR Code 2FA" className="w-44 h-44 bg-white p-2 rounded-xl" />
                  </div>
                )}
                {secret && (
                  <div className="mb-4 p-3 bg-dark-850 rounded-xl border border-white/[0.06]">
                    <p className="text-[10px] text-gray-500 mb-1">Código manual:</p>
                    <p className="text-xs font-mono text-white break-all select-all">{secret}</p>
                  </div>
                )}
                <button
                  onClick={() => setStep('verify')}
                  className="w-full py-2.5 rounded-xl bg-accent text-dark-900 font-semibold text-sm hover:bg-accent-300 transition-all"
                >
                  Já escaneei → Verificar
                </button>
              </>
            ) : (
              <>
                <div className="flex flex-col items-center mb-5">
                  <ShieldCheck className="w-10 h-10 text-accent mb-2" />
                  <p className="text-xs text-gray-400 text-center">
                    Digite o código de 6 dígitos gerado pelo app autenticador:
                  </p>
                </div>
                <input
                  type="text"
                  inputMode="numeric"
                  maxLength={6}
                  value={code}
                  onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
                  onKeyDown={(e) => e.key === 'Enter' && verify()}
                  placeholder="000 000"
                  className="w-full bg-dark-850 border border-white/10 rounded-xl px-4 py-3 text-center text-2xl tracking-[0.5em] font-mono text-white focus:outline-none focus:border-accent/50 mb-4"
                  autoFocus
                />
                <div className="flex gap-2">
                  <button onClick={() => { setStep('qr'); setCode('') }} className="flex-1 py-2.5 rounded-xl bg-dark-700 text-sm text-gray-400 hover:text-white transition-all">
                    ← Voltar
                  </button>
                  <button
                    onClick={verify}
                    disabled={loading || code.length < 6}
                    className="flex-1 py-2.5 rounded-xl bg-accent text-dark-900 font-semibold text-sm hover:bg-accent-300 transition-all disabled:opacity-50"
                  >
                    {loading ? <Loader2 className="w-4 h-4 animate-spin mx-auto" /> : 'Confirmar'}
                  </button>
                </div>
              </>
            )}
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  )
}
