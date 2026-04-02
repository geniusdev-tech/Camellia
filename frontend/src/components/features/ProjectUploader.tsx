'use client'

import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Upload, FileArchive, Loader2 } from 'lucide-react'

import { projectsAPI } from '@/lib/api'
import type { UploadedProject } from '@/lib/types'


function fmt(bytes: number) {
  if (!bytes) return '0 B'
  const k = 1024
  const s = ['B', 'KB', 'MB', 'GB']
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(k)), s.length - 1)
  return `${(bytes / k ** i).toFixed(1)} ${s[i]}`
}


function ProjectRow({ project }: { project: UploadedProject }) {
  const created = new Date(project.created_at)
  return (
    <div className="flex items-center justify-between rounded-xl border border-white/10 bg-dark-900/70 px-4 py-3">
      <div className="min-w-0">
        <div className="truncate text-sm font-medium text-white">{project.filename}</div>
        <div className="text-xs text-gray-400">
          {fmt(project.size_bytes)} · {created.toLocaleString()}
        </div>
      </div>
      <FileArchive className="h-4 w-4 shrink-0 text-accent" />
    </div>
  )
}


export function ProjectUploader() {
  const qc = useQueryClient()
  const [message, setMessage] = useState<string>('')

  const { data, isLoading } = useQuery({
    queryKey: ['projects'],
    queryFn: projectsAPI.list,
  })

  const uploadMutation = useMutation({
    mutationFn: projectsAPI.upload,
    onSuccess: () => {
      setMessage('Projeto enviado com sucesso.')
      qc.invalidateQueries({ queryKey: ['projects'] })
    },
    onError: (err) => {
      setMessage(err instanceof Error ? err.message : 'Falha no upload.')
    },
  })

  function onFileChange(file: File | null) {
    if (!file) return
    setMessage('')
    uploadMutation.mutate(file)
  }

  return (
    <section className="glass rounded-2xl p-5">
      <div className="mb-4 flex items-center justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold text-white">Projetos</h2>
          <p className="text-sm text-gray-400">Envie arquivos `.zip` para armazenar no backend.</p>
        </div>
        <label className="inline-flex cursor-pointer items-center gap-2 rounded-xl bg-accent px-4 py-2 text-sm font-medium text-dark-950">
          <Upload className="h-4 w-4" />
          Enviar .zip
          <input
            type="file"
            accept=".zip,application/zip"
            className="hidden"
            onChange={(e) => onFileChange(e.target.files?.[0] ?? null)}
          />
        </label>
      </div>

      {message ? <div className="mb-4 text-sm text-gray-300">{message}</div> : null}

      {uploadMutation.isPending ? (
        <div className="mb-4 flex items-center gap-2 text-sm text-gray-300">
          <Loader2 className="h-4 w-4 animate-spin" />
          Enviando projeto...
        </div>
      ) : null}

      <div className="space-y-3">
        {isLoading ? <div className="text-sm text-gray-400">Carregando uploads...</div> : null}
        {!isLoading && !(data?.projects?.length) ? (
          <div className="rounded-xl border border-dashed border-white/10 p-6 text-sm text-gray-400">
            Nenhum projeto enviado ainda.
          </div>
        ) : null}
        {data?.projects?.map((project) => (
          <ProjectRow key={project.id} project={project} />
        ))}
      </div>
    </section>
  )
}
