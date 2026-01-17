import { BrowserRouter, Routes, Route, Navigate, Outlet } from 'react-router-dom'
import { useAuthStore } from './store/authStore'
import Layout from './components/layout/Layout'
import LoginPage from './pages/LoginPage'
import DashboardPage from './pages/DashboardPage'
import SettingsPage from './pages/SettingsPage'

function App() {
    return (
        <BrowserRouter>
            <Routes>
                <Route path="/login" element={<LoginPage />} />
                <Route element={<PrivateRoute />}>
                    <Route element={<Layout />}>
                        <Route path="/" element={<DashboardPage />} />
                        <Route path="/settings" element={<SettingsPage />} />
                    </Route>
                </Route>
                <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
        </BrowserRouter>
    )
}

// Private route wrapper
function PrivateRoute() {
    const { isAuthenticated } = useAuthStore()

    if (!isAuthenticated) {
        return <Navigate to="/login" replace />
    }

    return <Outlet />
}

export default App
