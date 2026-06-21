import { createApp } from 'vue'
import PrimeVue from 'primevue/config'
import Aura from '@primevue/themes/aura'

import App from './App.vue'
import { createApiClient } from './lib/api.js'
import './assets/main.css'
import 'primeicons/primeicons.css'

const apiBaseUrl = import.meta.env.VITE_API_BASE_URL ?? ''
const app = createApp(App, { api: createApiClient(apiBaseUrl) })
app.use(PrimeVue, {
  theme: {
    preset: Aura,
  },
})
app.mount('#app')
