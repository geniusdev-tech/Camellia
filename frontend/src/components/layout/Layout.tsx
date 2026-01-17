import { Outlet, NavLink } from 'react-router-dom'
import { Menu, Shield, Home, Settings, LogOut, Moon, Sun } from 'lucide-react'
import { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { clsx } from 'clsx'
import { useAuthStore } from '../../store/authStore'
import { useThemeStore } from '../../store/themeStore'
import { authAPI } from '../../api/client'
import { useQueryClient } from '@tanstack/react-query'

export default function Layout() {
    const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false)
    const { user, logout } = useAuthStore()
    const { theme, toggleTheme } = useThemeStore()
    const queryClient = useQueryClient()

    // Close mobile menu on resize to desktop
    useEffect(() => {
        const handleResize = () => {
            if (window.innerWidth >= 1024) {
                setIsMobileMenuOpen(false)
            }
        }
        window.addEventListener('resize', handleResize)
        return () => window.removeEventListener('resize', handleResize)
    }, [])

    const handleLogout = async () => {
        try {
            await authAPI.logout()
            logout()
            queryClient.clear()
            setIsMobileMenuOpen(false)
        } catch (error) {
            console.error('Logout error:', error)
        }
    }

    const navItems = [
        { to: '/', icon: Home, label: 'Dashboard' },
        { to: '/settings', icon: Settings, label: 'Configurações' },
    ]

    const SidebarContent = () => (
        <div className="flex flex-col h-full bg-dark-900 border-r border-dark-800 text-white">
            {/* Brand */}
            <div className="h-16 flex items-center gap-3 px-6 border-b border-dark-800 bg-dark-950">
                <Shield className="w-8 h-8 text-primary-light" />
                <div>
                    <h1 className="text-lg font-bold">Camellia Shield</h1>
                    <p className="text-[10px] text-gray-400 uppercase tracking-wider">Enterprise Security</p>
                </div>
            </div>

            {/* Navigation */}
            <nav className="flex-1 px-3 py-6 space-y-1">
                <p className="px-3 mb-2 text-xs font-semibold text-gray-500 uppercase tracking-wider">Menu</p>
                {navItems.map((item) => (
                    <NavLink
                        key={item.to}
                        to={item.to}
                        onClick={() => setIsMobileMenuOpen(false)}
                        className={({ isActive }) =>
                            clsx(
                                'flex items-center gap-3 px-3 py-2.5 rounded-lg transition-all duration-200 group',
                                isActive
                                    ? 'bg-primary text-white shadow-lg shadow-primary/20'
                                    : 'text-gray-400 hover:text-white hover:bg-dark-800'
                            )
                        }
                    >
                        <item.icon className={clsx("w-5 h-5 flex-shrink-0 transition-colors")} />
                        <span className="font-medium">{item.label}</span>
                    </NavLink>
                ))}
            </nav>

            {/* User Footer */}
            {user && (
                <div className="p-4 border-t border-dark-800 bg-dark-950">
                    <div className="flex items-center gap-3 mb-3">
                        <div className="w-9 h-9 rounded-full bg-gradient-to-br from-primary to-primary-dark flex items-center justify-center border border-dark-700">
                            <span className="font-bold text-sm text-white">{user.email.charAt(0).toUpperCase()}</span>
                        </div>
                        <div className="flex-1 overflow-hidden">
                            <p className="text-sm font-medium text-white truncate">{user.email}</p>
                            <div className="flex items-center gap-1">
                                <div className={clsx("w-1.5 h-1.5 rounded-full", user.has_2fa ? "bg-secondary" : "bg-warning")} />
                                <p className="text-xs text-gray-400">{user.has_2fa ? 'Secured' : 'Unsecured'}</p>
                            </div>
                        </div>
                    </div>
                    <button
                        onClick={handleLogout}
                        className="flex items-center justify-center gap-2 w-full py-2 rounded-md bg-dark-800 text-gray-400 hover:text-white hover:bg-dark-700 transition-colors text-xs font-medium uppercase tracking-wide"
                    >
                        <LogOut className="w-3 h-3" />
                        Sair do Sistema
                    </button>
                </div>
            )}
        </div>
    )

    return (
        <div className="min-h-screen bg-gray-50 dark:bg-dark-950 flex">
            {/* Desktop Sidebar (Fixed) */}
            <aside className="hidden lg:block w-72 h-screen sticky top-0 shrink-0 shadow-xl z-30">
                <SidebarContent />
            </aside>

            {/* Mobile Sidebar (Drawer) */}
            <AnimatePresence>
                {isMobileMenuOpen && (
                    <>
                        <motion.div
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            exit={{ opacity: 0 }}
                            onClick={() => setIsMobileMenuOpen(false)}
                            className="fixed inset-0 bg-black/60 backdrop-blur-sm z-40 lg:hidden"
                        />
                        <motion.div
                            initial={{ x: '-100%' }}
                            animate={{ x: 0 }}
                            exit={{ x: '-100%' }}
                            transition={{ type: 'spring', damping: 25, stiffness: 300 }}
                            className="fixed top-0 left-0 h-full w-80 bg-dark-900 z-50 lg:hidden shadow-2xl"
                        >
                            <SidebarContent />
                        </motion.div>
                    </>
                )}
            </AnimatePresence>

            {/* Main Content Area */}
            <div className="flex-1 flex flex-col min-w-0">
                {/* Mobile Header / Desktop Topbar */}
                <header className="h-16 bg-white dark:bg-dark-900 border-b border-gray-200 dark:border-dark-800 flex items-center justify-between px-4 lg:px-8 sticky top-0 z-20 shadow-sm">
                    <div className="flex items-center gap-3">
                        {/* Mobile Hamburger */}
                        <button
                            onClick={() => setIsMobileMenuOpen(true)}
                            className="lg:hidden p-2 -ml-2 rounded-lg text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-dark-800"
                        >
                            <Menu className="w-6 h-6" />
                        </button>

                        {/* Page Title (could be dynamic) */}
                        <h2 className="text-lg font-semibold text-gray-800 dark:text-gray-100 lg:hidden">
                            Camellia Shield
                        </h2>
                    </div>

                    <div className="flex items-center gap-2 lg:gap-4">
                        {/* Theme Toggle */}
                        <button
                            onClick={toggleTheme}
                            className="p-2 rounded-full text-gray-500 hover:bg-gray-100 dark:hover:bg-dark-800 transition-colors"
                            title="Alternar Tema"
                        >
                            {theme === 'dark' ? (
                                <Sun className="w-5 h-5 text-yellow-500" />
                            ) : (
                                <Moon className="w-5 h-5 text-gray-600" />
                            )}
                        </button>
                    </div>
                </header>

                {/* Content Scroll Area */}
                <main className="flex-1 p-4 md:p-8 overflow-y-auto overflow-x-hidden">
                    <div className="max-w-6xl mx-auto space-y-6">
                        <Outlet />
                    </div>
                </main>
            </div>
        </div>
    )
}
