const configuredApiBase = import.meta.env.VITE_API_BASE_URL as string | undefined;

export const API_BASE_URL = configuredApiBase?.replace(/\/$/, '') || '';
export const API_BASE = `${API_BASE_URL}/api`;

export const apiUrl = (path: string) => {
  const normalizedPath = path.startsWith('/') ? path : `/${path}`;
  return `${API_BASE_URL}${normalizedPath}`;
};
