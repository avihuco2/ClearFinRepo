// Generates index.html from the compiled login page renderer
import { writeFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));

// Dynamic import of the compiled output
const { renderLoginPage } = await import('./dist/login-page.js');

const html = renderLoginPage({
  authLoginUrl: '/auth/login',
  dashboardUrl: '/dashboard',
  appOrigin: process.env.APP_ORIGIN || 'https://clearfin.click',
});

writeFileSync(resolve(__dirname, 'dist', 'index.html'), html, 'utf-8');
console.log('Generated dist/index.html');
