const defaultHeaders = {
  'Content-Type': 'application/json',
}

async function parseResponse(response) {
  const contentType = response.headers.get('content-type') || ''
  const payload = contentType.includes('application/json') ? await response.json() : await response.text()
  if (!response.ok) {
    const message = typeof payload === 'object' && payload && 'detail' in payload ? payload.detail : String(payload)
    throw new Error(message || `Request failed with status ${response.status}`)
  }
  return payload
}

export function createApiClient(baseUrl = '') {
  const normalizedBaseUrl = baseUrl.replace(/\/+$/, '')
  const rootUrl = normalizedBaseUrl || 'http://localhost:8000'
  return {
    async listAlgorithms() {
      const response = await fetch(`${normalizedBaseUrl}/algorithms`)
      return parseResponse(response)
    },
    async listPacks() {
      const response = await fetch(`${normalizedBaseUrl}/packs`)
      return parseResponse(response)
    },
    async reloadRuntime() {
      const response = await fetch(`${normalizedBaseUrl}/admin/reload`, {
        method: 'POST',
        headers: defaultHeaders,
        body: JSON.stringify({}),
      })
      return parseResponse(response)
    },
    async rebuildNative(payload = {}) {
      const response = await fetch(`${normalizedBaseUrl}/admin/rebuild-native`, {
        method: 'POST',
        headers: defaultHeaders,
        body: JSON.stringify(payload),
      })
      return parseResponse(response)
    },
    async listCatalogs(params = {}) {
      const query = new URLSearchParams()
      for (const [key, value] of Object.entries(params)) {
        if (value !== undefined && value !== null && value !== '') {
          query.set(key, String(value))
        }
      }
      const suffix = query.size > 0 ? `?${query.toString()}` : ''
      const response = await fetch(`${normalizedBaseUrl}/catalogs${suffix}`)
      return parseResponse(response)
    },
    async resolveHash(payload) {
      const response = await fetch(`${normalizedBaseUrl}/resolve`, {
        method: 'POST',
        headers: defaultHeaders,
        body: JSON.stringify(payload),
      })
      return parseResponse(response)
    },
    async searchHash(payload) {
      const response = await fetch(`${normalizedBaseUrl}/search-hash`, {
        method: 'POST',
        headers: defaultHeaders,
        body: JSON.stringify(payload),
      })
      return parseResponse(response)
    },
    async hashString(payload) {
      const response = await fetch(`${normalizedBaseUrl}/hash-string`, {
        method: 'POST',
        headers: defaultHeaders,
        body: JSON.stringify(payload),
      })
      return parseResponse(response)
    },
    async buildCatalogs(files) {
      const formData = new FormData()
      for (const file of files) {
        formData.append('binaries', file)
      }
      const response = await fetch(`${normalizedBaseUrl}/build-catalogs`, {
        method: 'POST',
        body: formData,
      })
      return parseResponse(response)
    },
    async exportEnum(payload) {
      const response = await fetch(`${normalizedBaseUrl}/export-enum`, {
        method: 'POST',
        headers: defaultHeaders,
        body: JSON.stringify(payload),
      })
      return parseResponse(response)
    },
    async bulkAuto(payload) {
      const response = await fetch(`${normalizedBaseUrl}/bulk-auto`, {
        method: 'POST',
        headers: defaultHeaders,
        body: JSON.stringify(payload),
      })
      return parseResponse(response)
    },
    async setPackActive(packName, active) {
      const response = await fetch(`${normalizedBaseUrl}/packs/${encodeURIComponent(packName)}`, {
        method: 'POST',
        headers: defaultHeaders,
        body: JSON.stringify({ active }),
      })
      return parseResponse(response)
    },
    async fetchOpenApi() {
      const response = await fetch(`${normalizedBaseUrl}/openapi.json`)
      return parseResponse(response)
    },
    swaggerUiUrl() {
      return `${rootUrl}/docs`
    },
    async validatePack(payload) {
      const response = await fetch(`${normalizedBaseUrl}/validate-pack`, {
        method: 'POST',
        headers: defaultHeaders,
        body: JSON.stringify(payload),
      })
      return parseResponse(response)
    },
  }
}
