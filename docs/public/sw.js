const cacheName = self.location.pathname
const pages = [

  "/quickstart/",
    "/install/",
    "/configuration/",
    "/client/",
    "/user/",
    "/",
    "/categories/",
    "/tags/",
    "/book.min.4d6d5ad3b0ae85d2a15b20ab217863f70db543e46314629e239ced759e674898.css",
  "/en.search-data.min.306cf90c79988dd5049b2fdde01ba70180cd93d9725717d5fa00ec76ade5f771.json",
  "/en.search.min.341d576d9d0fa3fc0e64d9ac46d2637f86d80f21c409734fc4ab6615fde12d8d.js",
  
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
