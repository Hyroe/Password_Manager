import { Route, Routes } from 'react-router-dom';

import App from '../App';

export function AppRouter() {
  return (
    <Routes>
      <Route path="*" element={<App />} />
    </Routes>
  );
}
