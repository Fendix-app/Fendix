const SITE_NAME = 'Acme Docs';

export function GET() {
  return new Response(`<h1>Welcome to ${SITE_NAME}</h1>`, { headers: { 'Content-Type': 'text/html; charset=utf-8' } }); // EVAL-SAFE
}
