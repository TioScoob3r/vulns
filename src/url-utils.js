export function isValidTestUrl(url) {
  try {
    const urlObj = new URL(url);
    return urlObj.search.includes('=') && !urlObj.hostname.includes('google.com');
  } catch {
    return false;
  }
}