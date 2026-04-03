'use client'

import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { FileArchive, Loader2, Upload } from 'lucide-react'
import { projectsAPI } from '@/lib/api'
import { FeedbackBanner } from '@/components/ui/FeedbackBanner'
import { useToastStore } from '@/store/toast'

export function ProjectUploader() {
  const qc = useQueryClient()
  const pushToast = useToastStore((state) => state.push)
  const [file, setFile] = useState<File | null>(null)
  const [packageName, setPackageName] = useState('')
  const [packageVersion, setPackageVersion] = useState('1.0.0')
  const [visibility, setVisibility] = useState<'private' | 'public' | 'shared'>('private')
  const [description, setDescription] = useState('')
  const [changelog, setChangelog] = useState('')
  const [metadata, setMetadata] = useState('{"channel":"stable"}')
  const [message, setMessage] = useState('')

  const uploadMutation = useMutation({
    mutationFn: projectsAPI.upload,
    onSuccess: (payload) => {
      const nextMessage =
        payload.deduplicated
          ? `Pacote já existia no repositório. Projeto ${payload.project?.package_name}@${payload.project?.package_version} reutilizado.`
          : `Upload concluído. Scan job: ${payload.scan_job_id || 'indisponível'}.`
      setMessage(nextMessage)
      pushToast('success', nextMessage)
      setFile(null)
      qc.invalidateQueries({ queryKey: ['projects'] })
      qc.invalidateQueries({ queryKey: ['jobs'] })
    },
    onError: (err) => {
      setMessage(err instanceof Error ? err.message : 'Falha no upload.')
    },
  })

  function submit() {
    if (!file) {
      setMessage('Selecione um arquivo .zip.')
      return
    }

    let parsedMetadata: Record<string, unknown> | undefined
    try {
      parsedMetadata = metadata.trim() ? JSON.parse(metadata) as Record<string, unknown> : undefined
    } catch {
      setMessage('Metadata deve ser um JSON válido.')
      pushToast('error', 'Metadata deve ser um JSON válido.')
      return
    }

    setMessage('')
    uploadMutation.mutate({
      file,
      packageName,
      packageVersion,
      visibility,
      description,
      changelog,
      metadata: parsedMetadata,
    })
  }

  return (
    <section className="glass rounded-2xl p-5">
      <div className="mb-5 flex items-start justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold text-white">Novo pacote</h2>
          <p className="text-sm text-gray-400">
            Envie um `.zip` com nome, versão, visibilidade e metadata para alimentar o workflow do repositório.
          </p>
        </div>
        <div className="flex h-11 w-11 items-center justify-center rounded-2xl bg-accent/10 text-accent">
          <Upload className="h-5 w-5" />
        </div>
      </div>

      <div className="grid gap-3 md:grid-cols-2">
        <label className="space-y-1 text-sm">
          <span className="text-gray-400">Pacote</span>
          <input
            value={packageName}
            onChange={(e) => setPackageName(e.target.value)}
            placeholder="acme-reports"
            className="w-full rounded-xl border border-white/10 bg-dark-900/70 px-3 py-2 text-white outline-none focus:border-accent/40"
          />
        </label>

        <label className="space-y-1 text-sm">
          <span className="text-gray-400">Versão</span>
          <input
            value={packageVersion}
            onChange={(e) => setPackageVersion(e.target.value)}
            placeholder="1.0.0"
            className="w-full rounded-xl border border-white/10 bg-dark-900/70 px-3 py-2 text-white outline-none focus:border-accent/40"
          />
        </label>

        <label className="space-y-1 text-sm md:col-span-2">
          <span className="text-gray-400">Descrição</span>
          <input
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Release inicial do pacote."
            className="w-full rounded-xl border border-white/10 bg-dark-900/70 px-3 py-2 text-white outline-none focus:border-accent/40"
          />
        </label>

        <label className="space-y-1 text-sm md:col-span-2">
          <span className="text-gray-400">Changelog</span>
          <textarea
            value={changelog}
            onChange={(e) => setChangelog(e.target.value)}
            rows={3}
            className="w-full rounded-xl border border-white/10 bg-dark-900/70 px-3 py-2 text-white outline-none focus:border-accent/40"
          />
        </label>

        <label className="space-y-1 text-sm">
          <span className="text-gray-400">Visibilidade</span>
          <select
            value={visibility}
            onChange={(e) => setVisibility(e.target.value as 'private' | 'public' | 'shared')}
            className="w-full rounded-xl border border-white/10 bg-dark-900/70 px-3 py-2 text-white outline-none focus:border-accent/40"
          >
            <option value="private">private</option>
            <option value="public">public</option>
            <option value="shared">shared</option>
          </select>
        </label>

        <label className="space-y-1 text-sm">
          <span className="text-gray-400">Arquivo ZIP</span>
          <input
            type="file"
            accept=".zip,application/zip"
            onChange={(e) => setFile(e.target.files?.[0] ?? null)}
            className="w-full rounded-xl border border-white/10 bg-dark-900/70 px-3 py-2 text-white outline-none file:mr-3 file:rounded-lg file:border-0 file:bg-accent/15 file:px-3 file:py-1.5 file:text-accent"
          />
        </label>

        <label className="space-y-1 text-sm md:col-span-2">
          <span className="text-gray-400">Metadata JSON</span>
          <textarea
            value={metadata}
            onChange={(e) => setMetadata(e.target.value)}
            rows={4}
            className="w-full rounded-xl border border-white/10 bg-dark-900/70 px-3 py-2 font-mono text-xs text-white outline-none focus:border-accent/40"
          />
        </label>
      </div>

      {message ? <div className="mt-4"><FeedbackBanner tone="info" message={message} /></div> : null}

      <div className="mt-4 flex items-center justify-between gap-3">
        <div className="flex items-center gap-2 text-xs text-gray-500">
          <FileArchive className="h-4 w-4 text-accent" />
          O backend valida ZIP, checksum, deduplicação e já dispara scan assíncrono.
        </div>
        <button
          onClick={submit}
          disabled={uploadMutation.isPending}
          className="inline-flex items-center gap-2 rounded-xl bg-accent px-4 py-2 text-sm font-medium text-dark-950 disabled:opacity-50"
        >
          {uploadMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Upload className="h-4 w-4" />}
          Publicar
        </button>
      </div>
    </section>
  )
}
