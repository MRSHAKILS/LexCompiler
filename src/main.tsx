import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import { installApiClient } from './apiClient';
import { LegalWorkspace } from './components/legal/LegalWorkspace';
import './index.css';

installApiClient();

// /legal is the lawyer's workspace on the product API; everything else is the demo dashboard.
const isLegal = window.location.pathname === '/legal' || window.location.pathname.startsWith('/legal/');

ReactDOM.createRoot(document.getElementById('root')!).render(<React.StrictMode>{isLegal ? <LegalWorkspace /> : <App />}</React.StrictMode>);
