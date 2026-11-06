export function renderResults(q: string): Response {
  return new Response(`<h1>Search results for ${q}</h1>`, { headers: { 'Content-Type': 'text/html; charset=utf-8' } }); // EVAL-SINK
}
