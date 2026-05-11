import rss from '@astrojs/rss';
import { getCollection } from 'astro:content';
import type { APIContext } from 'astro';

export async function GET(context: APIContext) {
  const posts = await getCollection('posts');
  const sorted = posts.sort((a, b) => b.data.date.getTime() - a.data.date.getTime());
  return rss({
    title: 'Karol Piątek - Swifty Friday',
    description: 'Notes from Karol Piątek on engineering velocity, AI dev tooling, and iOS architecture.',
    site: context.site!,
    items: sorted.map((post) => ({
      title: post.data.title,
      pubDate: post.data.date,
      description: post.data.description ?? '',
      link: post.data.redirectTo ?? `/${post.id}`,
    })),
  });
}
