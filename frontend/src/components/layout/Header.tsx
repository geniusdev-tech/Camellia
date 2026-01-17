import { Menu, X, Moon, Sun, Shield } from 'lucide-react'
import { motion, AnimatePresence } from 'framer-motion'
import { useThemeStore } from '../../store/themeStore'
import { useUIStore } from '../../store/uiStore'
import { useAuthStore } from '../../store/authStore'

export default function Header() {
    const { theme, toggleTheme } = useThemeStore()
    const { isMobileMenuOpen, toggleMobileMenu } = useUIStore()
    const { user } = useAuthStore()

    return (
        <header className="sticky top-0 z-40 h-16 bg-white dark:bg-dark-900 border-b border-gray-200 dark:border-dark-700 shadow-enterprise">
            <div className="flex items-center justify-between h-full px-4 lg:px-6">
                {/* Mobile Menu Button */}
                <button
                    onClick={toggleMobileMenu}
                    className="lg:hidden p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-dark-800 transition-colors"
                    aria-label="Toggle menu"
                >
                    {isMobileMenuOpen ? (
                        <X className="w-6 h-6 text-gray-700 dark:text-gray-300" />
                    ) : (
                        <Menu className="w-6 h-6 text-gray-700 dark:text-gray-300" />
                    )}
                </button>

                {/* Logo/Brand - Hidden on mobile when menu open */}
                <div className={`flex items-center gap-2 ${isMobileMenuOpen ? 'hidden lg:flex' : 'flex'}`}>
                    <Shield className="w-7 h-7 text-primary" />
                    <div className="hidden sm:block">
                        <h1 className="text-lg font-bold text-gray-900 dark:text-white">
                            Camellia Shield
                        </h1>
                        <p className="text-xs text-gray-500 dark:text-gray-400">Enterprise Security</p>
                    </div>
                </div>

                {/* Right Side Actions */}
                <div className="flex items-center gap-2">
                    {/* User Info - Desktop only */}
                    {user && (
                        <div className="hidden md:flex items-center gap-2 px-3 py-1.5 bg-surface dark:bg-dark-800 rounded-lg">
                            <div className="w-8 h-8 rounded-full bg-primary flex items-center justify-center">
                                <span className="text-xs font-bold text-white">
                                    {user.email.charAt(0).toUpperCase()}
                                </span>
                            </div>
                            <div className="hidden lg:block">
                                <p className="text-sm font-medium text-gray-900 dark:text-white truncate max-w-[150px]">
                                    {user.email}
                                </p>
                                {user.has_2fa && (
                                    <p className="text-xs text-secondary">🛡️ 2FA Active</p>
                                )}
                            </div>
                        </div>
                    )}

                    {/* Theme Toggle */}
                    <button
                        onClick={toggleTheme}
                        className="p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-dark-800 transition-colors"
                        aria-label="Toggle theme"
                    >
                        <AnimatePresence mode="wait">
                            {theme === 'dark' ? (
                                <motion.div
                                    key="sun"
                                    initial={{ rotate: -90, opacity: 0 }}
                                    animate={{ rotate: 0, opacity: 1 }}
                                    exit={{ rotate: 90, opacity: 0 }}
                                    transition={{ duration: 0.2 }}
                                >
                                    <Sun className="w-5 h-5 text-yellow-500" />
                                </motion.div>
                            ) : (
                                <motion.div
                                    key="moon"
                                    initial={{ rotate: 90, opacity: 0 }}
                                    animate={{ rotate: 0, opacity: 1 }}
                                    exit={{ rotate: -90, opacity: 0 }}
                                    transition={{ duration: 0.2 }}
                                >
                                    <Moon className="w-5 h-5 text-gray-600" />
                                </motion.div>
                            )}
                        </AnimatePresence>
                    </button>
                </div>
            </div>
        </header>
    )
}
