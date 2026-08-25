export function buildApiUrl(env: string, service: string, path: string, id: string): string {
  return `${env}/${service}/${path}/${id}`;
}

export async function callDynamic(a: string, b: string) {
  return fetch(buildApiUrl(a, b, "x", "y"));
}
