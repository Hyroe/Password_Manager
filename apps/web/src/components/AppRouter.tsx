import { Navigate, Route, Routes } from 'react-router-dom';

import App from '../App';

import { routes } from '../lib/routes';

export function AppRouter() {
  return (
    <Routes>
      <Route path={routes.home} element={<Navigate to={routes.login} replace />} />

      <Route path={routes.login} element={<App />} />

      <Route path={routes.register} element={<App />} />

      <Route path={routes.vault} element={<App />} />

      <Route path="/vault/items/:itemId" element={<App />} />

      <Route path={routes.security} element={<App />} />

      <Route path={routes.recovery} element={<App />} />

      <Route path="*" element={<Navigate to={routes.login} replace />} />
    </Routes>
  );
}
