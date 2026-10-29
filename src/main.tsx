import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import { installApiClient } from './apiClient';
import { LegalWorkspace } from './components/legal/LegalWorkspace';
import { AssistantSettings } from './components/settings/AssistantSettings';
import './index.css';

installApiClient();

// /legal is the lawyer's workspace and /settings connects coding assistants, both on the product
// API; everything else is the demo dashboard.
const at = (prefix: string) => window.location.pathname === prefix || window.location.pathname.startsWith(`${prefix}/`);
const page = at('/legal') ? <LegalWorkspace /> : at('/settings') ? <AssistantSettings /> : <App />;

ReactDOM.createRoot(document.getElementById('root')!).render(<React.StrictMode>{page}</React.StrictMode>);
