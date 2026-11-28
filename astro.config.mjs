import { defineConfig } from 'astro/config';
import sitemap from '@astrojs/sitemap';
import remarkGemoji from 'remark-gemoji';

// Posts are written with `#` for their sections, but the page title is the
// one real <h1>. Shift every heading down a level (h1 -> h2, h2 -> h3 ...)
// in any post that uses `#`, so each page has a single h1 and a correct
// outline for screen readers and search engines.
function rehypeDemoteHeadings() {
  const levels = ['h1', 'h2', 'h3', 'h4', 'h5', 'h6'];
  const walk = (node, fn) => {
    fn(node);
    (node.children ?? []).forEach((child) => walk(child, fn));
  };
  return (tree) => {
    let hasH1 = false;
    walk(tree, (n) => { if (n.type === 'element' && n.tagName === 'h1') hasH1 = true; });
    if (!hasH1) return;
    walk(tree, (n) => {
      if (n.type !== 'element') return;
      const i = levels.indexOf(n.tagName);
      if (i !== -1) n.tagName = levels[Math.min(i + 1, 5)];
    });
  };
}

export default defineConfig({
  site: 'https://swiftyfriday.com',
  trailingSlash: 'ignore',
  build: {
    format: 'directory',
  },
  integrations: [sitemap()],
  markdown: {
    remarkPlugins: [remarkGemoji],
    rehypePlugins: [rehypeDemoteHeadings],
    shikiConfig: {
      themes: {
        light: 'github-light',
        dark: 'github-dark',
      },
      wrap: false,
    },
  },
});
