export function getCachedResult(url) {
  return new Promise((resolve) => {
    chrome.storage.session.get([url], (data) => resolve(data[url] ?? null));
  });
}

export function setCachedResult(url, result) {
  chrome.storage.session.set({ [url]: result });
}
