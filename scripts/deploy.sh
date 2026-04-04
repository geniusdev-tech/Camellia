#!/bin/bash

##############################################################################
# GateStack Deploy Script
# Automatiza deploy do Frontend (Firebase) e Backend (Render)
# 
# Uso:
#   ./scripts/deploy.sh backend     # Deploy apenas backend
#   ./scripts/deploy.sh frontend    # Deploy apenas frontend
#   ./scripts/deploy.sh all         # Deploy completo
#   ./scripts/deploy.sh verify      # Verificar conexão
##############################################################################

set -e  # Exit on error

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configurações
BACKEND_URL="${BACKEND_URL:-https://gatestack-backend.onrender.com}"
FRONTEND_REPO="${FRONTEND_REPO:-seu-projeto-id}"
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

##############################################################################
# Funções Auxiliares
##############################################################################

log_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

log_success() {
    echo -e "${GREEN}✓${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

log_error() {
    echo -e "${RED}✗${NC} $1"
}

check_command() {
    if ! command -v $1 &> /dev/null; then
        log_error "$1 não está instalado"
        return 1
    fi
    return 0
}

##############################################################################
# Verificações Iniciais
##############################################################################

verify_setup() {
    log_info "Verificando setup..."
    
    # Verificar dependências
    check_command "node" || exit 1
    check_command "npm" || exit 1
    check_command "git" || exit 1
    
    log_success "Node v$(node -v)"
    log_success "npm v$(npm -v)"
    
    # Verificar se estamos no diretório correto
    if [ ! -f "$PROJECT_ROOT/package.json" ]; then
        log_error "package.json não encontrado em $PROJECT_ROOT"
        exit 1
    fi
    
    # Verificar git
    if [ ! -d "$PROJECT_ROOT/.git" ]; then
        log_error "Não estamos em um repositório git"
        exit 1
    fi
    
    log_success "Setup válido"
}

##############################################################################
# Verificar Conexão com Backend
##############################################################################

verify_backend() {
    log_info "Verificando backend em $BACKEND_URL..."
    
    if curl -s -f "$BACKEND_URL/health" > /dev/null 2>&1; then
        log_success "Backend está online ✓"
        
        # Tentar pegar versão
        VERSION=$(curl -s "$BACKEND_URL/health" | grep -o '"version":"[^"]*"' | cut -d'"' -f4 || echo "desconhecida")
        log_info "Versão: $VERSION"
        return 0
    else
        log_warning "Backend pode não estar acessível"
        log_info "Se é novo deploy, pode levar alguns minutos"
        return 1
    fi
}

##############################################################################
# Build e Deploy Backend (Render)
##############################################################################

deploy_backend() {
    log_info "Preparando deploy do backend..."
    
    # Ensure we're on main branch
    CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
    if [ "$CURRENT_BRANCH" != "main" ]; then
        log_warning "Você está na branch '$CURRENT_BRANCH', não em 'main'"
        read -p "Deseja continuar mesmo assim? (s/n) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Ss]$ ]]; then
            log_warning "Deploy cancelado"
            return 1
        fi
    fi
    
    # Check for uncommitted changes
    if ! git diff-index --quiet HEAD --; then
        log_warning "Você tem mudanças não commitadas"
        read -p "Deseja fazer commit automático? (s/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Ss]$ ]]; then
            git add -A
            git commit -m "Deploy: mudanças de código"
            log_success "Mudanças commitadas"
        else
            log_warning "Deploy cancelado"
            return 1
        fi
    fi
    
    # Push para main
    log_info "Fazendo push para GitHub..."
    git push origin main
    log_success "Push concluído"
    
    log_info "Backend será deployado automaticamente pelo Render"
    log_info "👉 Acompanhe em: https://dashboard.render.com"
    log_info "   Pode levar 5-15 minutos"
    
    # Esperar um pouco e verificar
    log_info "Aguardando 10 segundos antes de verificar..."
    sleep 10
    
    # Tentar verificar status
    if verify_backend; then
        log_success "Backend deployado com sucesso! ✓"
        return 0
    else
        log_warning "Backend ainda está iniciando, verifique em alguns minutos"
        return 0  # Não é erro, é normal levar tempo
    fi
}

##############################################################################
# Build e Deploy Frontend (Firebase)
##############################################################################

deploy_frontend() {
    log_info "Preparando deploy do frontend..."
    
    # Entrar no diretório frontend
    cd "$PROJECT_ROOT/frontend" || exit 1
    
    # Verificar se Firebase CLI está instalado
    check_command "firebase" || {
        log_error "Firebase CLI não está instalado"
        log_info "Instale com: npm install -g firebase-tools"
        return 1
    }
    
    log_success "Firebase CLI encontrado"
    
    # Instalar dependências se necessário
    if [ ! -d "node_modules" ]; then
        log_info "Instalando dependências do frontend..."
        npm install
    fi
    
    # Build para produção
    log_info "Building frontend para produção..."
    npm run build
    log_success "Build concluído"
    
    # Deploy no Firebase
    log_info "Deployando no Firebase..."
    firebase deploy --only hosting || {
        log_error "Erro ao fazer deploy no Firebase"
        return 1
    }
    
    log_success "Frontend deployado com sucesso! ✓"
    
    # Mostrar URLs
    FIREBASE_PROJECT=$(grep -m1 '"default"' .firebaserc | grep -o ':.*' | grep -o '"[^"]*"' | sed 's/"//g')
    log_success "Seu frontend está em: https://${FIREBASE_PROJECT}.firebaseapp.com"
    
    return 0
}

##############################################################################
# Deploy Completo
##############################################################################

deploy_all() {
    log_info "======================================"
    log_info "  DEPLOY COMPLETO - Backend + Frontend"
    log_info "======================================"
    echo
    
    read -p "Tem certeza que quer fazer deploy completo? (s/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Ss]$ ]]; then
        log_warning "Deploy cancelado"
        return 1
    fi
    
    # Backend primeiro (mais rápido, menos dependências)
    log_info "Etapa 1/2: Deployando Backend..."
    if deploy_backend; then
        log_success "Backend ok"
    else
        log_error "Falha no backend"
        return 1
    fi
    
    echo
    
    # Frontend depois
    log_info "Etapa 2/2: Deployando Frontend..."
    if deploy_frontend; then
        log_success "Frontend ok"
    else
        log_error "Falha no frontend"
        return 1
    fi
    
    echo
    log_success "======================================"
    log_success "  DEPLOY COMPLETO FINALIZADO! 🎉"
    log_success "======================================"
    echo
    log_info "URLs de acesso:"
    log_info "  Backend:  $BACKEND_URL"
    log_info "  Frontend: Verifique acima"
    echo
}

##############################################################################
# Menu Interativo
##############################################################################

show_menu() {
    echo
    echo -e "${BLUE}=== GateStack Deploy ${NC}"
    echo "1) Deploy Backend (Render)"
    echo "2) Deploy Frontend (Firebase)"
    echo "3) Deploy Completo (Backend + Frontend)"
    echo "4) Verificar Saúde (Health Check)"
    echo "5) Sair"
    echo
    read -p "Escolha uma opção (1-5): " choice
    
    case $choice in
        1)
            deploy_backend
            ;;
        2)
            deploy_frontend
            ;;
        3)
            deploy_all
            ;;
        4)
            verify_backend
            ;;
        5)
            log_info "Até logo!"
            exit 0
            ;;
        *)
            log_error "Opção inválida"
            show_menu
            ;;
    esac
}

##############################################################################
# Main
##############################################################################

main() {
    verify_setup
    
    # Se não houver argumento, mostrar menu
    if [ $# -eq 0 ]; then
        show_menu
        return
    fi
    
    # Processar argumentos
    case "$1" in
        backend)
            deploy_backend
            ;;
        frontend)
            deploy_frontend
            ;;
        all)
            deploy_all
            ;;
        verify)
            verify_backend
            ;;
        help)
            echo "Uso: $0 [comando]"
            echo
            echo "Comandos:"
            echo "  backend              Deploy apenas backend"
            echo "  frontend             Deploy apenas frontend"
            echo "  all                  Deploy completo"
            echo "  verify               Verificar saúde do backend"
            echo "  help                 Mostrar esta mensagem"
            ;;
        *)
            log_error "Comando desconhecido: $1"
            echo "Use: $0 help"
            exit 1
            ;;
    esac
}

# Execute
main \"$@\"
