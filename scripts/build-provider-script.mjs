import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { build } from 'vite'

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url))
const root = path.resolve(scriptDirectory, '..')

await build({
  configFile: false,
  publicDir: false,
  logLevel: 'warn',
  build: {
    target: 'es2018',
    minify: false,
    sourcemap: false,
    emptyOutDir: false,
    outDir: path.join(root, 'public'),
    lib: {
      entry: path.join(scriptDirectory, 'provider-api-subscription.js'),
      name: 'ProviderApiSubscription',
      formats: ['iife'],
      fileName: () => 'provider-api-subscription.js',
    },
    rolldownOptions: {
      output: {
        footer: 'var operator = ProviderApiSubscription.operator;',
      },
    },
  },
})
