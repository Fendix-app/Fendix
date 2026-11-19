async function fetchPreview(url) {
  const upstream = await fetch(url); // EVAL-SINK
  return { status: upstream.status, body: await upstream.text() };
}

module.exports = { fetchPreview };
