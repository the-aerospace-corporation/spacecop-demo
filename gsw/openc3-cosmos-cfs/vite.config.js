import { defineConfig } from 'vite'
import VitePluginStyleInject from 'vite-plugin-style-inject'
import vue from '@vitejs/plugin-vue'

const DEFAULT_EXTENSIONS = ['.mjs', '.js', '.ts', '.jsx', '.tsx', '.json']

export default defineConfig({
  build: {
    outDir: 'tools/widgets/IdslogWidget',
    emptyOutDir: true,
    sourcemap: true,
    lib: {
      entry: './src/IdslogWidget.vue',
      name: 'IdslogWidget',
      fileName: (format, entryName) => `${entryName}.${format}.min.js`,
      formats: ['umd'],
    },
    rollupOptions: {
      // OpenC3 provides ONLY vue + vuetify to a widget at runtime; everything
      // else (@openc3/vue-common and its deps: single-spa, pinia, vue-router)
      // must be BUNDLED. Externalizing single-spa/pinia/vue-router made the
      // bundled vue-common Widget mixin reach for runtime globals that aren't
      // there (single-spa comes in as null) -> the component throws on setup and
      // renders nothing. Keep this list to exactly vue + vuetify.
      external: ['vue', 'vuetify'],
    },
  },
  plugins: [vue(), VitePluginStyleInject()],
  resolve: {
    extensions: [...DEFAULT_EXTENSIONS, '.vue'], // not recommended but saves us from having to change every SFC import
  },
})
