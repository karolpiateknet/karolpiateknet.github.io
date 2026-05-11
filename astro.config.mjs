import { defineConfig } from 'astro/config';
import sitemap from '@astrojs/sitemap';
import remarkGemoji from 'remark-gemoji';

export default defineConfig({
  site: 'https://swiftyfriday.com',
  trailingSlash: 'ignore',
  build: {
    format: 'directory',
  },
  integrations: [sitemap()],
  markdown: {
    remarkPlugins: [remarkGemoji],
    shikiConfig: {
      themes: {
        light: 'github-light',
        dark: 'github-dark',
      },
      wrap: true,
    },
  },
});
