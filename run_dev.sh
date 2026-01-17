#!/bin/bash
# Script para rodar Camellia Shield em modo desenvolvimento

cd "$(dirname "$0")"

# Ativar virtualenv se não estiver ativo
if [ -z "$VIRTUAL_ENV" ]; then
    echo "Ativando virtualenv..."
    source .venv/bin/activate
fi

# Configurar modo desenvolvimento
export FLASK_ENV=development
export FLASK_DEBUG=1
export DESKTOP_MODE=0
export HOST=0.0.0.0  # Permite acesso de qualquer dispositivo na rede

# Descobrir IP local
LOCAL_IP=$(hostname -I | awk '{print $1}')

echo "🚀 Iniciando Camellia Shield (Development Mode)..."
echo ""
echo "📍 Acesso Local:  http://localhost:5000"
echo "📱 Acesso na Rede: http://$LOCAL_IP:5000"
echo ""
echo "💡 Acesse de qualquer dispositivo conectado no seu WiFi!"
echo ""

python app.py
