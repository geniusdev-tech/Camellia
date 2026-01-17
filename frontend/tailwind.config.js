/** @type {import('tailwindcss').Config} */
export default {
    content: [
        "./index.html",
        "./src/**/*.{js,ts,jsx,tsx}",
    ],
    darkMode: 'class',
    theme: {
        extend: {
            colors: {
                // Enterprise Security Palette
                primary: {
                    DEFAULT: '#1E3A8A',
                    dark: '#1E293B',
                    light: '#3B82F6'
                },
                secondary: {
                    DEFAULT: '#059669',
                    dark: '#047857',
                    light: '#10B981'
                },
                danger: {
                    DEFAULT: '#DC2626',
                    dark: '#B91C1C',
                    light: '#EF4444'
                },
                warning: {
                    DEFAULT: '#F59E0B',
                    dark: '#D97706',
                    light: '#FBBF24'
                },
                dark: {
                    950: '#020617',
                    900: '#0F172A',
                    800: '#1E293B',
                    700: '#334155',
                    600: '#475569',
                    500: '#64748B'
                },
                surface: {
                    DEFAULT: '#F8FAFC',
                    dark: '#E2E8F0'
                }
            },
            animation: {
                'fade-in': 'fadeIn 0.2s ease-in-out',
                'slide-up': 'slideUp 0.3s ease-out',
                'slide-down': 'slideDown 0.3s ease-out',
                'slide-in-left': 'slideInLeft 0.3s ease-out',
                'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
                'bounce-subtle': 'bounceSubtle 2s infinite'
            },
            keyframes: {
                fadeIn: {
                    '0%': { opacity: '0' },
                    '100%': { opacity: '1' }
                },
                slideUp: {
                    '0%': { transform: 'translateY(10px)', opacity: '0' },
                    '100%': { transform: 'translateY(0)', opacity: '1' }
                },
                slideDown: {
                    '0%': { transform: 'translateY(-10px)', opacity: '0' },
                    '100%': { transform: 'translateY(0)', opacity: '1' }
                },
                slideInLeft: {
                    '0%': { transform: 'translateX(-100%)' },
                    '100%': { transform: 'translateX(0)' }
                },
                bounceSubtle: {
                    '0%, 100%': { transform: 'translateY(0)' },
                    '50%': { transform: 'translateY(-5px)' }
                }
            },
            boxShadow: {
                'enterprise': '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)',
                'enterprise-lg': '0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05)'
            }
        },
    },
    plugins: [],
}
