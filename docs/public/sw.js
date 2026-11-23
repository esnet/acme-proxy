const cacheName = self.location.pathname
const pages = [

  "/getting-started/",
    "/quickstart/",
    "/client-guides/",
    "/install/",
    "/configuration/",
    "/client/",
    "/user/",
    "/",
    "/categories/",
    "/tags/",
    "/book.min.744580663b76732a2e0d75f87cbd539117d0ba6f0564f993fe275aa1967a6766.css",
  "/en.search-data.min.b7a29a2de9380c71ef49e3ac2114934184598fd97ecca41e11f07e08bf0eec57.json",
  "/en.search.min.e6ce9daea50b7485960ff23c0fd90de407693b15976eff8b77511d1e222df010.js",
  
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
