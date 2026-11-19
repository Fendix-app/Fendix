export async function fetchPreview(url: string) {
  const upstream = await fetch(url); // EVAL-SINK
  return { status: upstream.status, body: await upstream.text() };
}
