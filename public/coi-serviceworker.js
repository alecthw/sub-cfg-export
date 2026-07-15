/* Migration tombstone for versions that used coi-serviceworker. */
if (typeof window === 'undefined') {
  self.addEventListener('install', () => self.skipWaiting())
  self.addEventListener('activate', (event) => {
    event.waitUntil(self.registration.unregister())
  })
} else if ('serviceWorker' in navigator) {
  navigator.serviceWorker.getRegistrations().then((registrations) => {
    for (const registration of registrations) {
      const workers = [registration.installing, registration.waiting, registration.active]
      if (
        workers.some(
          (worker) => worker && new URL(worker.scriptURL).pathname.endsWith('/coi-serviceworker.js'),
        )
      ) {
        void registration.unregister()
      }
    }
  })
}
