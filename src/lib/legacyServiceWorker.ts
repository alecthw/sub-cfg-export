const LEGACY_SCRIPT_NAME = '/coi-serviceworker.js'

function isLegacyWorker(worker: ServiceWorker | null): boolean {
  if (!worker) return false
  try {
    return new URL(worker.scriptURL).pathname.endsWith(LEGACY_SCRIPT_NAME)
  } catch {
    return false
  }
}

function isLegacyRegistration(registration: ServiceWorkerRegistration): boolean {
  return [registration.installing, registration.waiting, registration.active].some(isLegacyWorker)
}

export async function unregisterLegacyServiceWorker(): Promise<void> {
  if (!('serviceWorker' in navigator)) return

  try {
    const registrations = await navigator.serviceWorker.getRegistrations()
    await Promise.all(
      registrations
        .filter(isLegacyRegistration)
        .map((registration) => registration.unregister()),
    )
  } catch {
    // Service Worker cleanup must never prevent the extractor from starting.
  }
}
