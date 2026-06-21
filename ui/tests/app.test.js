import { mount } from '@vue/test-utils'
import { nextTick } from 'vue'
import PrimeVue from 'primevue/config'
import Aura from '@primevue/themes/aura'

import App from '../src/App.vue'

if (!window.matchMedia) {
  Object.defineProperty(window, 'matchMedia', {
    writable: true,
    value: vi.fn().mockImplementation((query) => ({
      matches: false,
      media: query,
      onchange: null,
      addListener: vi.fn(),
      removeListener: vi.fn(),
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      dispatchEvent: vi.fn(),
    })),
  })
}

async function flushPromises() {
  await Promise.resolve()
  await nextTick()
}

test('uses simplified workflow with shared library DataTable and conditional base fields', async () => {
  const openSpy = vi.spyOn(window, 'open').mockImplementation(() => null)
  let resolveSearchRequest
  let resolveHashStringRequest
  const searchRequestPromise = new Promise((resolve) => {
    resolveSearchRequest = resolve
  })
  const hashStringRequestPromise = new Promise((resolve) => {
    resolveHashStringRequest = resolve
  })
  const api = {
    listAlgorithms: vi.fn().mockResolvedValue([
      {
        id: 'payouts_king_crc32',
        display_name: 'Payouts King CRC32',
        implementation_type: 'python',
        supports_base_values: false,
      },
      {
        id: 'param_crc32',
        display_name: 'Param CRC32',
        implementation_type: 'python',
        supports_base_values: true,
      },
    ]),
    listPacks: vi.fn().mockResolvedValue([
      { name: 'default-pack', version: '0.1.0', path: '/packs/default-pack', active: true },
    ]),
    listCatalogs: vi.fn().mockResolvedValue([
      { binary_family: 'pe', library: 'kernel32.dll', export_count: 2, symbols: ['CreateFileW', 'GetProcAddress'] },
      { binary_family: 'pe', library: 'api-ms-win-core-file-l1-2-0.dll', export_count: 1, symbols: ['CreateFileW'] },
      { kind: 'wordlist', library: 'payouts_king_wordlist', export_count: 3, symbols: ['-backup'] },
    ]),
    searchHash: vi.fn().mockImplementation(() => searchRequestPromise),
    hashString: vi.fn().mockImplementation(() => hashStringRequestPromise),
    exportEnum: vi.fn().mockResolvedValue({
      exports: [{ library: 'kernel32.dll', base_value: 32, header_text: 'typedef enum {\n  demo = 1,\n} demo;' }],
    }),
    setPackActive: vi.fn().mockResolvedValue({ name: 'default-pack', active: false }),
    swaggerUiUrl: vi.fn().mockReturnValue('http://localhost:8000/docs'),
  }

  const wrapper = mount(App, {
    props: { api },
    global: {
      plugins: [[PrimeVue, { theme: { preset: Aura } }]],
    },
  })
  await flushPromises()

  await wrapper.get('[data-test="tab-docs"]').trigger('click')
  await flushPromises()
  expect(openSpy).toHaveBeenCalledWith('http://localhost:8000/docs', '_blank', 'noopener,noreferrer')

  expect(wrapper.text()).not.toContain('Resolve Hash')
  expect(wrapper.get('input[name="commonWindowsDllsOnly"]').element.checked).toBe(true)
  expect(wrapper.find('textarea[name="searchBaseValues"]').exists()).toBe(false)

  await wrapper.get('input[type="radio"][value="param_crc32"]').setValue(true)
  await flushPromises()

  expect(wrapper.find('textarea[name="searchBaseValues"]').exists()).toBe(true)

  await wrapper.get('input[name="searchHashValue"]').setValue('0x6789')
  await wrapper.get('textarea[name="searchBaseValues"]').setValue('0x20')
  await wrapper.get('[data-test="search-form"]').trigger('submit.prevent')
  await nextTick()

  expect(wrapper.find('[data-test="search-progress"]').exists()).toBe(true)
  resolveSearchRequest({
    results: [{ algorithm_id: 'param_crc32', library: 'kernel32.dll', symbol: 'CreateFileW', base_value: 32 }],
  })
  await flushPromises()

  expect(api.searchHash).toHaveBeenLastCalledWith({
    hash_value: '0x6789',
    library_names: ['kernel32.dll'],
    algorithm_params: { base_values: ['0x20'] },
  })
  expect(wrapper.find('[data-test="search-progress"]').exists()).toBe(false)

  await wrapper.get('input[name="hashStringValue"]').setValue('GetProcAddress')
  await wrapper.get('textarea[name="hashBaseValues"]').setValue('0x20')
  await wrapper.get('[data-test="hash-string-form"]').trigger('submit.prevent')
  await nextTick()

  expect(wrapper.find('[data-test="hash-string-progress"]').exists()).toBe(true)
  resolveHashStringRequest({
    results: [{ library_name: 'kernel32.dll', symbol_name: 'GetProcAddress', hash_value_hex: '0x1234', base_value: 32 }],
  })
  await flushPromises()

  expect(api.hashString).toHaveBeenLastCalledWith({
    algorithm_id: 'param_crc32',
    symbol_name: 'GetProcAddress',
    library_names: ['kernel32.dll'],
    algorithm_params: { base_values: ['0x20'] },
  })
  expect(wrapper.find('[data-test="hash-string-progress"]').exists()).toBe(false)

  await wrapper.get('[data-test="library-row-api-ms-win-core-file-l1-2-0.dll"]').setValue(true)
  await flushPromises()
  await wrapper.get('input[name="excludeHyphenatedDlls"]').setValue(true)
  await flushPromises()

  await wrapper.get('[data-test="tab-export"]').trigger('click')
  await wrapper.get('textarea[name="exportBaseValues"]').setValue('0x20')
  await wrapper.get('[data-test="export-form"]').trigger('submit.prevent')
  await flushPromises()

  expect(api.exportEnum).toHaveBeenLastCalledWith({
    algorithm_id: 'param_crc32',
    library_names: ['kernel32.dll'],
    algorithm_params: { base_values: ['0x20'] },
  })
  expect(wrapper.find('[data-test="export-copy-0"]').exists()).toBe(true)
  expect(wrapper.find('[data-test="export-download-0"]').exists()).toBe(true)

  await wrapper.get('[data-test="tab-packs"]').trigger('click')
  await flushPromises()
  expect(wrapper.text()).toContain('Explore Catalogue')
  expect(wrapper.find('input[name="catalogFilter"]').exists()).toBe(true)
  expect(wrapper.text()).toContain('kernel32.dll')

  await wrapper.get('input[name="pack-default-pack"]').setValue(false)
  await flushPromises()

  expect(api.setPackActive).toHaveBeenCalledWith('default-pack', false)
  openSpy.mockRestore()
})
