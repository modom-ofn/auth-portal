export async function oidcConfigAPI(path, data) {
  const response = await fetch('/api/admin/' + path, {
    credentials: 'same-origin',
    method: data === undefined ? 'GET' : 'PUT',
    headers: {'Content-Type': 'application/json'},
    body: data === undefined ? undefined : JSON.stringify(data)
  });
  const result = await response.json();
  if (!response.ok || result.ok === false) throw new Error(result.error || 'Request failed');
  return result;
}
