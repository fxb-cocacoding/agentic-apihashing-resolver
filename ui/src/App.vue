<script setup>
import { computed, nextTick, onMounted, ref, watch } from 'vue'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import InputText from 'primevue/inputtext'
import { FilterMatchMode } from '@primevue/core/api'

const props = defineProps({
  api: { type: Object, required: true },
})

const tabs = [
  { id: 'workbench', label: 'Hashes' },
  { id: 'export', label: 'Export Enum' },
  { id: 'packs', label: 'Packs' },
  { id: 'docs', label: 'Docs' },
]

const COMMON_WINDOWS_API_DLLS = new Set([
  'advapi32.dll',
  'bcrypt.dll',
  'combase.dll',
  'crypt32.dll',
  'gdi32.dll',
  'kernel32.dll',
  'kernelbase.dll',
  'ntdll.dll',
  'ole32.dll',
  'oleaut32.dll',
  'rpcrt4.dll',
  'shell32.dll',
  'shlwapi.dll',
  'user32.dll',
  'winhttp.dll',
  'wininet.dll',
  'ws2_32.dll',
])

const activeTab = ref('workbench')
const algorithms = ref([])
const catalogs = ref([])
const packs = ref([])
const selectedAlgorithm = ref('')
const error = ref('')
const libraryRowsPerPage = ref(25)
const catalogRowsPerPage = ref(25)
const catalogsDirty = ref(false)
const updatingPacks = ref([])
const catalogsLoading = ref(false)
const reloadInFlight = ref(false)
const rebuildInFlight = ref(false)

const commonWindowsDllsOnly = ref(true)
const excludeHyphenatedDlls = ref(false)
const selectedLibraries = ref([])
const didAutoSelectCommonLibraries = ref(false)
const algorithmFilter = ref('')
const libraryTableRef = ref(null)
const visibleSelectableLibraries = ref([])
const librarySortMeta = ref([
  { field: 'selected', order: -1 },
  { field: 'library', order: 1 },
])

const searchHashValue = ref('')
const searchBaseValues = ref('')
const searchResults = ref([])
const searchInFlight = ref(false)

const hashStringValue = ref('')
const hashBaseValues = ref('')
const hashStringResults = ref([])
const hashStringInFlight = ref(false)

const exportBaseValues = ref('')
const exportResults = ref([])

const libraryFilters = ref({
  global: { value: null, matchMode: FilterMatchMode.CONTAINS },
  library: { value: null, matchMode: FilterMatchMode.CONTAINS },
  kind_or_family: { value: null, matchMode: FilterMatchMode.CONTAINS },
  export_count: { value: null, matchMode: FilterMatchMode.CONTAINS },
})

const catalogFilters = ref({
  global: { value: null, matchMode: FilterMatchMode.CONTAINS },
  library: { value: null, matchMode: FilterMatchMode.CONTAINS },
  kind_or_family: { value: null, matchMode: FilterMatchMode.CONTAINS },
  export_count: { value: null, matchMode: FilterMatchMode.CONTAINS },
})

const selectedAlgorithmRecord = computed(() =>
  algorithms.value.find((algorithm) => algorithm.id === selectedAlgorithm.value) ?? null,
)

const selectedAlgorithmSupportsBaseValues = computed(() => Boolean(selectedAlgorithmRecord.value?.supports_base_values))

const swaggerDocsUrl = computed(() =>
  props.api.swaggerUiUrl ? props.api.swaggerUiUrl() : 'http://localhost:8000/docs',
)

const libraryRows = computed(() => {
  const merged = new Map()
  const selectedSet = new Set(selectedLibraries.value)
  for (const entry of catalogs.value) {
    if (entry.kind === 'wordlist') {
      continue
    }
    const existing = merged.get(entry.library)
    const exportCount = Number(entry.export_count ?? entry.symbols?.length ?? 0)
    if (existing) {
      existing.export_count = Math.max(existing.export_count, exportCount)
      continue
    }
    merged.set(entry.library, {
      library: entry.library,
      kind_or_family: entry.binary_family || 'library',
      export_count: exportCount,
      has_hyphen: entry.library.includes('-'),
      is_common_windows: COMMON_WINDOWS_API_DLLS.has(entry.library.toLowerCase()),
      selected: selectedSet.has(entry.library),
    })
  }
  for (const row of merged.values()) {
    row.selected = selectedSet.has(row.library)
  }
  return Array.from(merged.values()).sort((left, right) => left.library.localeCompare(right.library))
})

const catalogRows = computed(() =>
  catalogs.value.map((entry) => ({
    library: entry.library,
    kind_or_family: entry.kind || entry.binary_family || 'library',
    export_count: Number(entry.export_count ?? entry.symbols?.length ?? 0),
  })),
)

const filteredAlgorithms = computed(() => {
  const query = algorithmFilter.value.trim().toLowerCase()
  if (!query) {
    return algorithms.value
  }
  return algorithms.value.filter((algorithm) => {
    const fields = [
      algorithm.id,
      algorithm.display_name,
      algorithm.pack,
      algorithm.author,
      algorithm.source,
    ]
    return fields.some((field) => String(field ?? '').toLowerCase().includes(query))
  })
})

const allLibrariesSelected = computed(() =>
  visibleSelectableLibraries.value.length > 0
  && visibleSelectableLibraries.value.every((library) => selectedLibraries.value.includes(library)),
)

function buildRowsPerPageOptions(totalRows) {
  const options = [25, 50, 100, 500, 1000]
  if (totalRows > 0 && !options.includes(totalRows)) {
    options.push(totalRows)
  }
  return options
}

const libraryRowsPerPageOptions = computed(() => buildRowsPerPageOptions(libraryRows.value.length))
const catalogRowsPerPageOptions = computed(() => buildRowsPerPageOptions(catalogRows.value.length))

function clearError() {
  error.value = ''
}

function handleTabClick(tab) {
  if (tab.id === 'docs') {
    window.open(swaggerDocsUrl.value, '_blank', 'noopener,noreferrer')
    return
  }
  activeTab.value = tab.id
}

function withArrayField(name, values) {
  return values.length > 0 ? { [name]: values } : {}
}

function parseBaseValues(text) {
  const values = text
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean)
  if (values.length === 0) {
    return undefined
  }
  return { base_values: values }
}

function sanitizeSelectedLibraries() {
  const available = new Set(libraryRows.value.map((row) => row.library))
  selectedLibraries.value = selectedLibraries.value.filter((library) => available.has(library))
}

function applyCommonWindowsLibraryPreselection() {
  const preselected = libraryRows.value
    .filter((row) => row.is_common_windows)
    .map((row) => row.library)
    .filter((library) => !excludeHyphenatedDlls.value || !library.includes('-'))
  selectedLibraries.value = Array.from(new Set(preselected))
}

function toggleLibrarySelection(library, enabled) {
  if (enabled) {
    if (excludeHyphenatedDlls.value && library.includes('-')) {
      return
    }
    if (!selectedLibraries.value.includes(library)) {
      selectedLibraries.value.push(library)
    }
    return
  }
  selectedLibraries.value = selectedLibraries.value.filter((item) => item !== library)
}

function toggleAllLibraries(enabled) {
  const visible = visibleSelectableLibraries.value
  if (enabled) {
    const nextSelected = new Set(selectedLibraries.value)
    for (const library of visible) {
      nextSelected.add(library)
    }
    selectedLibraries.value = Array.from(nextSelected)
    return
  }
  const blocked = new Set(visible)
  selectedLibraries.value = selectedLibraries.value.filter((library) => !blocked.has(library))
}

function readVisibleSelectableLibraries() {
  const root = libraryTableRef.value?.$el ?? libraryTableRef.value
  if (!root) {
    return []
  }
  const nodes = root.querySelectorAll('input[data-test^="library-row-"]')
  return Array.from(nodes)
    .filter((node) => !node.disabled)
    .map((node) => String(node.getAttribute('data-test') || '').replace('library-row-', ''))
    .filter(Boolean)
}

async function refreshVisibleSelectableLibraries() {
  await nextTick()
  visibleSelectableLibraries.value = readVisibleSelectableLibraries()
}

function clearHiddenBaseValues() {
  if (selectedAlgorithmSupportsBaseValues.value) {
    return
  }
  searchBaseValues.value = ''
  hashBaseValues.value = ''
  exportBaseValues.value = ''
}

function formatBase(baseValue) {
  if (baseValue === undefined || baseValue === null) {
    return ''
  }
  return `base: 0x${Number(baseValue).toString(16)}`
}

function algorithmLanguageLabel(algorithm) {
  return algorithm?.implementation_type === 'c_shared' ? 'c' : 'python'
}

async function copyEnumHeader(headerText) {
  const text = headerText ?? ''
  if (!text) {
    return
  }
  if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
    await navigator.clipboard.writeText(text)
    return
  }
  const fallback = document.createElement('textarea')
  fallback.value = text
  fallback.setAttribute('readonly', 'readonly')
  fallback.style.position = 'fixed'
  fallback.style.left = '-9999px'
  document.body.appendChild(fallback)
  fallback.select()
  document.execCommand('copy')
  document.body.removeChild(fallback)
}

function toSafeFileToken(value) {
  return String(value ?? '')
    .toLowerCase()
    .replace(/[^a-z0-9_]+/g, '_')
    .replace(/^_+|_+$/g, '')
}

function enumFileName(item) {
  const libraryToken = toSafeFileToken(item?.library || 'library')
  const algorithmToken = toSafeFileToken(selectedAlgorithm.value || 'algorithm')
  const baseToken = item?.base_value !== undefined && item?.base_value !== null
    ? `_base_${Number(item.base_value).toString(16)}`
    : ''
  return `${libraryToken}_${algorithmToken}${baseToken}.h`
}

function downloadEnumHeader(item) {
  const headerText = item?.header_text ?? ''
  if (!headerText) {
    return
  }
  const blob = new Blob([headerText], { type: 'text/plain;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = enumFileName(item)
  document.body.appendChild(link)
  link.click()
  document.body.removeChild(link)
  URL.revokeObjectURL(url)
}

function toResultList(response) {
  if (Array.isArray(response?.results)) {
    return response.results
  }
  if (response && typeof response === 'object' && 'hash_value_hex' in response) {
    return [response]
  }
  return []
}

function toExportList(response) {
  if (Array.isArray(response?.exports)) {
    return response.exports
  }
  if (response && typeof response === 'object' && 'header_text' in response) {
    return [response]
  }
  return []
}

async function loadCatalogs() {
  catalogsLoading.value = true
  try {
    catalogs.value = await props.api.listCatalogs()
  } finally {
    catalogsLoading.value = false
  }
}

function ensureSelectedAlgorithm() {
  const stillAvailable = algorithms.value.some((algorithm) => algorithm.id === selectedAlgorithm.value)
  if (stillAvailable) {
    return
  }
  selectedAlgorithm.value = algorithms.value[0]?.id ?? ''
}

async function loadAlgorithms() {
  algorithms.value = await props.api.listAlgorithms()
  ensureSelectedAlgorithm()
}

function refreshCatalogsInBackground() {
  void loadCatalogs()
    .then(() => {
      catalogsDirty.value = false
    })
    .catch((err) => {
      error.value = err instanceof Error ? err.message : String(err)
    })
}

async function loadInitialData() {
  const [packPayload] = await Promise.all([
    props.api.listPacks(),
  ])
  packs.value = packPayload
  await loadAlgorithms()
  await loadCatalogs()
}

async function submitSearch() {
  clearError()
  if (!searchHashValue.value.trim()) {
    error.value = 'Hash value is required.'
    return
  }
  searchInFlight.value = true
  try {
    const algorithmParams = selectedAlgorithmSupportsBaseValues.value ? parseBaseValues(searchBaseValues.value) : undefined
    const payload = {
      hash_value: searchHashValue.value.trim(),
      ...withArrayField('library_names', selectedLibraries.value),
      ...(algorithmParams ? { algorithm_params: algorithmParams } : {}),
    }
    const startedAt = performance.now()
    const response = await props.api.searchHash(payload)
    const elapsedMs = Math.round(performance.now() - startedAt)
    console.log('[apihashing] Search Hash', {
      execution_mode: response.execution_mode ?? 'unknown',
      worker_count: response.worker_count ?? null,
      algorithm_count: response.algorithm_count ?? null,
      elapsed_ms: elapsedMs,
      request: payload,
      output: response,
    })
    searchResults.value = response.results ?? []
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  } finally {
    searchInFlight.value = false
  }
}

async function submitHashString() {
  clearError()
  if (!hashStringValue.value.trim()) {
    error.value = 'String is required.'
    return
  }
  hashStringInFlight.value = true
  try {
    const algorithmParams = selectedAlgorithmSupportsBaseValues.value ? parseBaseValues(hashBaseValues.value) : undefined
    const response = await props.api.hashString({
      algorithm_id: selectedAlgorithm.value,
      symbol_name: hashStringValue.value.trim(),
      ...withArrayField('library_names', selectedLibraries.value),
      ...(algorithmParams ? { algorithm_params: algorithmParams } : {}),
    })
    hashStringResults.value = toResultList(response)
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  } finally {
    hashStringInFlight.value = false
  }
}

async function submitExport() {
  clearError()
  if (selectedLibraries.value.length === 0) {
    error.value = 'Select at least one library.'
    return
  }
  try {
    const algorithmParams = selectedAlgorithmSupportsBaseValues.value ? parseBaseValues(exportBaseValues.value) : undefined
    const response = await props.api.exportEnum({
      algorithm_id: selectedAlgorithm.value,
      library_names: selectedLibraries.value,
      ...(algorithmParams ? { algorithm_params: algorithmParams } : {}),
    })
    exportResults.value = toExportList(response)
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  }
}

async function togglePack(pack) {
  if (updatingPacks.value.includes(pack.name)) {
    return
  }
  clearError()
  updatingPacks.value = [...updatingPacks.value, pack.name]
  try {
    await props.api.setPackActive(pack.name, !pack.active)
    packs.value = await props.api.listPacks()
    await loadAlgorithms()
    await loadCatalogs()
    catalogsDirty.value = false
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  } finally {
    updatingPacks.value = updatingPacks.value.filter((name) => name !== pack.name)
  }
}

async function refreshRuntimeViews() {
  packs.value = await props.api.listPacks()
  await loadAlgorithms()
  await loadCatalogs()
  catalogsDirty.value = false
}

async function triggerRuntimeReload() {
  if (reloadInFlight.value || rebuildInFlight.value) {
    return
  }
  clearError()
  reloadInFlight.value = true
  try {
    await props.api.reloadRuntime()
    await refreshRuntimeViews()
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  } finally {
    reloadInFlight.value = false
  }
}

async function triggerNativeRebuild() {
  if (reloadInFlight.value || rebuildInFlight.value) {
    return
  }
  clearError()
  rebuildInFlight.value = true
  try {
    await props.api.rebuildNative({})
    await refreshRuntimeViews()
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  } finally {
    rebuildInFlight.value = false
  }
}

watch(catalogs, () => {
  sanitizeSelectedLibraries()
  if (!didAutoSelectCommonLibraries.value && commonWindowsDllsOnly.value) {
    applyCommonWindowsLibraryPreselection()
    didAutoSelectCommonLibraries.value = true
  }
})

watch(commonWindowsDllsOnly, (enabled) => {
  if (enabled) {
    applyCommonWindowsLibraryPreselection()
  }
})

watch(excludeHyphenatedDlls, (enabled) => {
  if (enabled) {
    selectedLibraries.value = selectedLibraries.value.filter((library) => !library.includes('-'))
  }
  void refreshVisibleSelectableLibraries()
})

watch(selectedAlgorithmSupportsBaseValues, () => {
  clearHiddenBaseValues()
})

watch(activeTab, async (tabId) => {
  if (tabId !== 'packs' && catalogsDirty.value) {
    refreshCatalogsInBackground()
  }
  if (tabId === 'workbench' || tabId === 'export') {
    void refreshVisibleSelectableLibraries()
  }
})

watch(libraryRows, () => {
  void refreshVisibleSelectableLibraries()
})

onMounted(async () => {
  await loadInitialData()
  clearHiddenBaseValues()
  await refreshVisibleSelectableLibraries()
})
</script>

<template>
  <main class="shell">
    <section class="hero panel">
      <p class="eyebrow">Malware Analysis</p>
      <h1>api hashing</h1>
      <p class="lede">Search and hash API values with shared library selection.</p>
    </section>

    <p v-if="error" class="error panel">{{ error }}</p>

    <section class="workspace">
      <div class="main-column">
        <section class="panel tabs-panel">
          <div class="tab-list" role="tablist" aria-label="api hashing workflows">
            <button
              v-for="tab in tabs"
              :key="tab.id"
              :data-test="`tab-${tab.id}`"
              class="tab-button"
              :class="{ active: activeTab === tab.id }"
              type="button"
              @click="handleTabClick(tab)"
            >
              {{ tab.label }}
            </button>
          </div>

          <section v-if="activeTab === 'workbench' || activeTab === 'export'" class="library-selector panel">
            <div class="library-selector-head">
              <h2>Libraries</h2>
              <p class="selected-algorithm">Selected: {{ selectedLibraries.length }}</p>
            </div>
            <div class="library-options">
              <label>
                <input v-model="commonWindowsDllsOnly" name="commonWindowsDllsOnly" type="checkbox" />
                Common Windows API DLLs only
              </label>
              <label>
                <input v-model="excludeHyphenatedDlls" name="excludeHyphenatedDlls" type="checkbox" />
                Exclude DLLs with `-` in name
              </label>
            </div>
            <DataTable
              ref="libraryTableRef"
              v-model:rows="libraryRowsPerPage"
              v-model:filters="libraryFilters"
              v-model:multiSortMeta="librarySortMeta"
              :value="libraryRows"
              dataKey="library"
              paginator
              :rowsPerPageOptions="libraryRowsPerPageOptions"
              filterDisplay="row"
              :globalFilterFields="['library', 'kind_or_family', 'export_count']"
              sortMode="multiple"
              size="small"
              class="library-table"
              @page="refreshVisibleSelectableLibraries"
              @filter="refreshVisibleSelectableLibraries"
              @sort="refreshVisibleSelectableLibraries"
            >
              <template #header>
                <div class="catalog-header-filter">
                  <InputText v-model="libraryFilters.global.value" name="libraryFilter" placeholder="Global filter" />
                </div>
              </template>
              <Column field="selected" header="Use" sortable :showFilterMenu="false" style="width: 8rem">
                <template #body="{ data }">
                  <input
                    :data-test="`library-row-${data.library}`"
                    type="checkbox"
                    :checked="selectedLibraries.includes(data.library)"
                    :disabled="excludeHyphenatedDlls && data.has_hyphen"
                    @change="toggleLibrarySelection(data.library, $event.target.checked)"
                  />
                </template>
                <template #filter>
                  <label class="select-all-checkbox">
                    <input
                      data-test="library-select-all"
                      type="checkbox"
                      :checked="allLibrariesSelected"
                      @change="toggleAllLibraries($event.target.checked)"
                    />
                    <span>All</span>
                  </label>
                </template>
              </Column>
              <Column field="library" header="Library" sortable>
                <template #filter="{ filterModel, filterCallback }">
                  <InputText v-model="filterModel.value" placeholder="Filter library" @input="filterCallback()" />
                </template>
              </Column>
              <Column field="kind_or_family" header="Type" sortable>
                <template #filter="{ filterModel, filterCallback }">
                  <InputText v-model="filterModel.value" placeholder="Filter type" @input="filterCallback()" />
                </template>
              </Column>
              <Column field="export_count" header="Exports" sortable>
                <template #filter="{ filterModel, filterCallback }">
                  <InputText v-model="filterModel.value" placeholder="Filter exports" @input="filterCallback()" />
                </template>
              </Column>
            </DataTable>
          </section>

          <section v-if="activeTab === 'workbench'" class="tab-section">
            <div class="subpanel">
              <h2>Search Hash</h2>
              <p class="selected-algorithm">Algorithm set: all loaded algorithms</p>
              <form data-test="search-form" class="resolve-form" @submit.prevent="submitSearch">
                <label>
                  <span>Hash Value</span>
                  <input v-model="searchHashValue" name="searchHashValue" type="text" />
                </label>
                <label v-if="selectedAlgorithmSupportsBaseValues">
                  <span>Base Values</span>
                  <textarea v-model="searchBaseValues" name="searchBaseValues" rows="2" placeholder="0x10, 0x20" />
                </label>
                <button type="submit" :disabled="searchInFlight">Search</button>
              </form>
              <div v-if="searchInFlight" data-test="search-progress" class="request-progress">
                <progress class="request-progress-bar" />
                <span>Searching…</span>
              </div>
              <ul class="match-list compact-list">
                <li v-for="match in searchResults" :key="`${match.algorithm_id}:${match.library}:${match.symbol}`">
                  <strong>{{ match.algorithm_id }}</strong>
                  <span>{{ match.library }}!{{ match.symbol }}</span>
                  <small v-if="selectedAlgorithmSupportsBaseValues && match.base_value !== undefined && match.base_value !== null">{{ formatBase(match.base_value) }}</small>
                </li>
              </ul>
            </div>

            <div class="subpanel">
              <h2>Hash String</h2>
              <p class="selected-algorithm">Algorithm: {{ selectedAlgorithm }}</p>
              <form data-test="hash-string-form" class="resolve-form" @submit.prevent="submitHashString">
                <label>
                  <span>String</span>
                  <input v-model="hashStringValue" name="hashStringValue" type="text" />
                </label>
                <label v-if="selectedAlgorithmSupportsBaseValues">
                  <span>Base Values</span>
                  <textarea v-model="hashBaseValues" name="hashBaseValues" rows="2" placeholder="0x10, 0x20" />
                </label>
                <button type="submit" :disabled="hashStringInFlight">Hash</button>
              </form>
              <div v-if="hashStringInFlight" data-test="hash-string-progress" class="request-progress">
                <progress class="request-progress-bar" />
                <span>Hashing…</span>
              </div>
              <ul class="match-list compact-list">
                <li v-for="item in hashStringResults" :key="`${item.library_name}:${item.symbol_name}`">
                  <strong>{{ item.library_name || '' }}</strong>
                  <span>0x{{ item.hash_value_hex }}</span>
                  <small v-if="selectedAlgorithmSupportsBaseValues && item.base_value !== undefined && item.base_value !== null">{{ formatBase(item.base_value) }}</small>
                </li>
              </ul>
            </div>
          </section>

          <section v-else-if="activeTab === 'export'" class="tab-section">
            <div class="subpanel">
              <h2>Export Enum</h2>
              <p class="selected-algorithm">Algorithm: {{ selectedAlgorithm }}</p>
              <form data-test="export-form" class="resolve-form" @submit.prevent="submitExport">
                <label v-if="selectedAlgorithmSupportsBaseValues">
                  <span>Base Values</span>
                  <textarea v-model="exportBaseValues" name="exportBaseValues" rows="2" placeholder="0x10, 0x20" />
                </label>
                <button type="submit">Export Enum</button>
              </form>
              <div v-for="(item, index) in exportResults" :key="`${item.library}:${item.base_value ?? 'none'}`" class="export-block">
                <p v-if="selectedAlgorithmSupportsBaseValues && item.base_value !== undefined && item.base_value !== null" class="selected-algorithm">Base 0x{{ Number(item.base_value).toString(16) }}</p>
                <div class="code-wrap">
                  <div class="code-actions">
                    <button
                      :data-test="`export-copy-${index}`"
                      class="text-icon-button"
                      type="button"
                      title="Copy enum"
                      @click="copyEnumHeader(item.header_text)"
                    >
                      <span aria-hidden="true">⧉</span>
                    </button>
                    <button
                      :data-test="`export-download-${index}`"
                      class="text-icon-button"
                      type="button"
                      title="Download enum"
                      @click="downloadEnumHeader(item)"
                    >
                      <span aria-hidden="true">⇩</span>
                    </button>
                  </div>
                  <pre class="catalog-json">{{ item.header_text }}</pre>
                </div>
              </div>
            </div>
          </section>

          <section v-else-if="activeTab === 'packs'" class="tab-section">
            <div class="subpanel">
              <div class="panel-head">
                <h2>Packs</h2>
                <p class="selected-algorithm">Session-only activation</p>
              </div>
              <div class="pack-actions">
                <button type="button" :disabled="reloadInFlight || rebuildInFlight" @click="triggerRuntimeReload">
                  {{ reloadInFlight ? 'Reloading…' : 'Reload Runtime' }}
                </button>
                <button type="button" :disabled="reloadInFlight || rebuildInFlight" @click="triggerNativeRebuild">
                  {{ rebuildInFlight ? 'Rebuilding…' : 'Rebuild Native + Reload' }}
                </button>
              </div>
              <p class="selected-algorithm">No Docker restart required after edits.</p>
              <ul class="match-list compact-list">
                <li v-for="pack in packs" :key="pack.name">
                  <label>
                    <input
                      :checked="pack.active"
                      :disabled="updatingPacks.includes(pack.name)"
                      :name="`pack-${pack.name}`"
                      type="checkbox"
                      @change="togglePack(pack)"
                    />
                    {{ pack.name }} · {{ pack.version }}
                  </label>
                </li>
              </ul>
            </div>
            <div class="subpanel">
              <div class="panel-head">
                <h2>Explore Catalogue</h2>
                <p class="selected-algorithm">Loaded from active packs</p>
              </div>
              <DataTable
                v-model:rows="catalogRowsPerPage"
                v-model:filters="catalogFilters"
                :value="catalogRows"
                paginator
                :rowsPerPageOptions="catalogRowsPerPageOptions"
                dataKey="library"
                filterDisplay="row"
                :globalFilterFields="['library', 'kind_or_family', 'export_count']"
                size="small"
              >
                <template #header>
                  <div class="catalog-header-filter">
                    <InputText v-model="catalogFilters.global.value" name="catalogFilter" placeholder="Global filter" />
                  </div>
                </template>
                <Column field="library" header="Library" sortable>
                  <template #filter="{ filterModel, filterCallback }">
                    <InputText v-model="filterModel.value" placeholder="Filter library" @input="filterCallback()" />
                  </template>
                </Column>
                <Column field="kind_or_family" header="Type" sortable>
                  <template #filter="{ filterModel, filterCallback }">
                    <InputText v-model="filterModel.value" placeholder="Filter type" @input="filterCallback()" />
                  </template>
                </Column>
                <Column field="export_count" header="Exports" sortable>
                  <template #filter="{ filterModel, filterCallback }">
                    <InputText v-model="filterModel.value" placeholder="Filter exports" @input="filterCallback()" />
                  </template>
                </Column>
              </DataTable>
            </div>
          </section>
        </section>
      </div>

      <aside class="side-column panel hash-sidebar">
        <div class="panel-head">
          <h2>Algorithms</h2>
          <span class="chip" v-if="selectedAlgorithmRecord">{{ selectedAlgorithmRecord.implementation_type }}</span>
        </div>
        <InputText v-model="algorithmFilter" name="algorithmFilter" placeholder="Filter API hashes" />
        <ul class="algorithm-list">
          <li v-for="algorithm in filteredAlgorithms" :key="algorithm.id">
            <label class="algorithm-card">
              <input v-model="selectedAlgorithm" type="radio" name="algorithm" :value="algorithm.id" />
              <div>
                <strong>{{ algorithm.display_name }}</strong>
                <p class="meta">{{ algorithm.id }}</p>
                <div class="algorithm-tags">
                  <span class="chip">lang: {{ algorithmLanguageLabel(algorithm) }}</span>
                  <span class="chip">pack: {{ algorithm.pack }}</span>
                  <span class="chip">author: {{ algorithm.author || 'unknown' }}</span>
                </div>
                <p class="meta">
                  Source:
                  <a v-if="algorithm.source" :href="algorithm.source" class="meta-link" target="_blank" rel="noopener noreferrer">
                    {{ algorithm.source }}
                  </a>
                  <span v-else>n/a</span>
                </p>
              </div>
            </label>
          </li>
        </ul>
      </aside>
    </section>
  </main>
</template>
