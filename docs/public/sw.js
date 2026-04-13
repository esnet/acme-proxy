const cacheName = self.location.pathname
const pages = [

  "/quickstart/",
  "/install/",
  "/user/",
  "/client/",
  "/examples/",
  "/firewall/",
  "/",
  "/categories/",
  "/tags/",
  "/book.min.4d6d5ad3b0ae85d2a15b20ab217863f70db543e46314629e239ced759e674898.css",
  "/en.search-data.min.0386fa07ad3ad6c84c365e20597b97291a94d042e64eeb3527e16537bd9127ab.json",
  "/en.search.min.4c7b822b52c27e45dcc401576e8748248407109c1dbb914b25910930a668c107.js",
  
];

self.addEventListener("install", function (event) {
  self.skipWaiting();

  caches.open(cacheName).then((cache) => {
    return cache.addAll(pages);
  });
});

self.addEventListener("fetch", (event) => {
  const request = event.request;
  if (request.method !== "GET") {
    return;
  }

  /**
   * @param {Response} response
   * @returns {Promise<Response>}
   */
  function saveToCache(response) {
    if (cacheable(response)) {
      return caches
        .open(cacheName)
        .then((cache) => cache.put(request, response.clone()))
        .then(() => response);
    } else {
      return response;
    }
  }

  /**
   * @param {Error} error
   */
  function serveFromCache(error) {
    return caches.open(cacheName).then((cache) => cache.match(request.url));
  }

  /**
   * @param {Response} response
   * @returns {Boolean}
   */
  function cacheable(response) {
    return response.type === "basic" && response.ok && !response.headers.has("Content-Disposition")
  }

  event.respondWith(fetch(request).then(saveToCache).catch(serveFromCache));
});
