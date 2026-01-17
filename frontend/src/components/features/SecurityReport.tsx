import { clsx } from "clsx"
import { Shield, AlertTriangle, CheckCircle, FileX, Info } from "lucide-react"

interface IntegrityReport {
    success: boolean
    filename: string
    hashes: {
        sha256: string
        blake2b: string
    }
    integrity: {
        signature_valid: boolean
        signature_msg: string
        entropy: number
    }
    risk_analysis: {
        level: "LOW" | "HIGH" | "CRITICAL"
        factors: string[]
    }
}

export default function SecurityReport({ report }: { report: IntegrityReport }) {
    if (!report.success) return <div className="text-danger">Erro na análise</div>

    const riskColor = {
        LOW: "text-secondary bg-secondary/10 border-secondary/20",
        HIGH: "text-warning bg-warning/10 border-warning/20",
        CRITICAL: "text-danger bg-danger/10 border-danger/20"
    }[report.risk_analysis.level]

    return (
        <div className="space-y-6">
            {/* Risk Badge */}
            <div className={clsx("p-4 rounded-xl border flex items-center gap-4", riskColor)}>
                {report.risk_analysis.level === "LOW" ? <Shield className="w-8 h-8" /> : <AlertTriangle className="w-8 h-8" />}
                <div>
                    <h3 className="font-bold text-lg">Nível de Risco: {report.risk_analysis.level}</h3>
                    <p className="text-sm opacity-90">
                        {report.risk_analysis.level === "LOW"
                            ? "A integridade do arquivo parece sólida."
                            : "Atenção: Anomalias detectadas neste arquivo."}
                    </p>
                </div>
            </div>

            {/* Critical Factors */}
            {report.risk_analysis.factors.length > 0 && (
                <div className="bg-white dark:bg-dark-800 p-4 rounded-xl border border-danger/20">
                    <h4 className="font-semibold text-danger flex items-center gap-2 mb-2">
                        <FileX className="w-4 h-4" /> Fatores de Risco
                    </h4>
                    <ul className="list-disc list-inside space-y-1 text-sm text-gray-700 dark:text-gray-300">
                        {report.risk_analysis.factors.map((f, i) => (
                            <li key={i}>{f}</li>
                        ))}
                    </ul>
                </div>
            )}

            {/* Integrity Details */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="bg-gray-50 dark:bg-dark-900 p-4 rounded-lg border border-gray-200 dark:border-dark-700">
                    <h4 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3">Assinatura Digital</h4>
                    <div className="space-y-3">
                        <div>
                            <span className="text-xs text-gray-400 block mb-1">SHA-256 Hash</span>
                            <code className="text-[10px] bg-white dark:bg-dark-800 p-1.5 rounded border border-gray-200 dark:border-dark-700 block break-all font-mono">
                                {report.hashes.sha256}
                            </code>
                        </div>
                        <div>
                            <span className="text-xs text-gray-400 block mb-1">BLAKE2b Hash (Integrity)</span>
                            <code className="text-[10px] bg-white dark:bg-dark-800 p-1.5 rounded border border-gray-200 dark:border-dark-700 block break-all font-mono">
                                {report.hashes.blake2b}
                            </code>
                        </div>
                    </div>
                </div>

                <div className="bg-gray-50 dark:bg-dark-900 p-4 rounded-lg border border-gray-200 dark:border-dark-700">
                    <h4 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3">Análise Heurística</h4>
                    <div className="space-y-3">
                        <div className="flex justify-between items-center text-sm">
                            <span className="text-gray-600 dark:text-gray-400">Verificação Magic Bytes</span>
                            {report.integrity.signature_valid ? (
                                <span className="text-secondary flex items-center gap-1"><CheckCircle className="w-3 h-3" /> Válido</span>
                            ) : (
                                <span className="text-danger flex items-center gap-1"><FileX className="w-3 h-3" /> Inválido</span>
                            )}
                        </div>
                        <div className="flex justify-between items-center text-sm">
                            <span className="text-gray-600 dark:text-gray-400">Entropia (Shannon)</span>
                            <span className={clsx("font-mono", report.integrity.entropy > 7.5 ? "text-warning" : "text-gray-600 dark:text-gray-400")}>
                                {report.integrity.entropy} / 8.0
                            </span>
                        </div>
                        <div className="text-[10px] text-gray-400 p-2 bg-white dark:bg-dark-800 rounded">
                            <Info className="w-3 h-3 inline mr-1" />
                            {report.integrity.signature_msg}
                        </div>
                    </div>
                </div>
            </div>
        </div>
    )
}
