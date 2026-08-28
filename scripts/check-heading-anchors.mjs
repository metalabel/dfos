#!/usr/bin/env node
// Guards against dead cross-document links into the corpus the site serves.
//
// Every `https://protocol.dfos.com/...` URL in this repo names a page the site
// renders and, when it carries a `#fragment`, a heading anchor that page emits.
// Both rot silently: a renamed section, a folded spec, or a change to the slug
// rules leaves a link that still resolves — to the top of the wrong page, or to
// nothing. Four such breaks shipped before this check existed, and one of them
// was created by a fix: teaching the renderer to decode HTML entities before
// slugging (so `api:<host>` slugs to `apihost`) silently invalidated every
// anchor authored against the pre-fix slug.
//
// That is why the slug pipeline below is a deliberate duplicate of the site
// renderer's heading logic (packages/site-protocol/src/lib/renderSpec.ts) —
// same marked inline parse, same tag strip, same entity decode, same
// github-slugger instance per document. It MUST track that renderer: if the two
// ever disagree, the renderer is right and this file is the bug.
//
// Everything else is derived, never hardcoded — the route set comes from the
// site's own pages, public assets, and redirects; each route's markdown source
// comes from the registry or from the `readFileSync` call in its page. A new
// spec is covered the moment it is registered.
//
// Not checked: anchors on relative `./FOO.md#section` links. Those are read on
// github.com, whose slugger sees the raw markdown rather than the site's
// rendered HTML, so the two renderers can legitimately disagree. Relative
// markdown links are checked for file existence only.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import GithubSlugger from 'github-slugger';
import { Marked } from 'marked';

const SITE = 'packages/site-protocol';
const PAGES_DIR = join(SITE, 'src/pages');
const PUBLIC_DIR = join(SITE, 'public');
const REGISTRY = join(SITE, 'src/content/specs.ts');
const ASTRO_CONFIG = join(SITE, 'astro.config.ts');

const SCAN_EXTENSIONS = ['.md', '.astro', '.ts', '.tsx'];
const SKIP_DIRS = new Set([
  'node_modules',
  'dist',
  '.git',
  '.astro',
  '.turbo',
  '.build',
  '.claude',
  'notes.local',
]);

// ---------------------------------------------------------------------------
// Slug derivation — mirrors renderSpec.ts's heading renderer exactly.
// ---------------------------------------------------------------------------

function decodeHtmlEntities(s) {
  return s
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&amp;/g, '&');
}

/** Every heading id one markdown document renders to, in document order. */
function headingAnchors(markdown) {
  const slugger = new GithubSlugger();
  const ids = new Set();
  const marked = new Marked({
    renderer: {
      heading(token) {
        const plain = this.parser.parseInline(token.tokens).replace(/<[^>]*>/g, '');
        ids.add(slugger.slug(decodeHtmlEntities(plain)));
        return '';
      },
      // The renderer restores the literal tilde instead of <del>; a heading
      // carrying one slugs with it, so the same override belongs here.
      del(token) {
        return `~${this.parser.parseInline(token.tokens)}`;
      },
      // Code blocks cannot contain headings and the real renderer highlights
      // them asynchronously; skipping the work keeps this check synchronous.
      code() {
        return '';
      },
    },
  });
  marked.parse(markdown);
  return ids;
}

// ---------------------------------------------------------------------------
// The served corpus — derived from the site's own configuration.
// ---------------------------------------------------------------------------

/** Registry slug → markdown source path, both taken from specs.ts. */
function registrySources() {
  const text = readFileSync(REGISTRY, 'utf8');
  const sources = new Map();
  let slug = null;
  for (const m of text.matchAll(/\bslug:\s*'([^']+)'|\bsource:\s*'([^']+)'/g)) {
    if (m[1] !== undefined) slug = m[1];
    else if (slug) sources.set(slug, resolve(SITE, m[2]));
  }
  return sources;
}

/**
 * Routes the site serves, and the markdown behind them where there is any.
 * Pages whose body is built in the component (the landing page, the FAQ) are
 * real routes with no markdown file to resolve anchors against.
 */
function siteRoutes() {
  const routes = new Set();
  const markdown = registrySources();

  for (const name of readdirSync(PAGES_DIR)) {
    const route = '/' + name.replace(/\.astro$/, '').replace(/\.ts$/, '');
    routes.add(route === '/index' ? '/' : route);

    // A page that reads its own markdown (the deploy guide, the agent skill)
    // carries no `source` in the registry — that field feeds llms-full.txt.
    if (!name.endsWith('.astro')) continue;
    const page = readFileSync(join(PAGES_DIR, name), 'utf8');
    const read = /readFileSync\(\s*'([^']+\.md)'/.exec(page);
    if (read) markdown.set('/' + name.replace(/\.astro$/, ''), resolve(SITE, read[1]));
  }

  for (const asset of readdirSync(PUBLIC_DIR)) routes.add('/' + asset);

  const config = readFileSync(ASTRO_CONFIG, 'utf8');
  const redirects = /redirects:\s*\{([\s\S]*?)\}/.exec(config);
  if (redirects) {
    for (const m of redirects[1].matchAll(/'([^']+)':/g)) routes.add(m[1]);
  }

  for (const route of markdown.keys()) routes.add(route);
  return { routes, markdown };
}

// ---------------------------------------------------------------------------

function walk(dir, out = []) {
  for (const entry of readdirSync(dir)) {
    if (SKIP_DIRS.has(entry)) continue;
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) walk(path, out);
    else if (SCAN_EXTENSIONS.some((ext) => path.endsWith(ext))) out.push(path);
  }
  return out;
}

const { routes, markdown } = siteRoutes();

const anchorCache = new Map();
function anchorsOf(file) {
  if (!anchorCache.has(file)) {
    // The skill page renders its body with the YAML frontmatter stripped.
    const source = readFileSync(file, 'utf8').replace(/^---\n[\s\S]*?\n---\n/, '');
    anchorCache.set(file, headingAnchors(source));
  }
  return anchorCache.get(file);
}

const offenders = [];
function report(file, index, text, link, reason) {
  offenders.push({
    path: relative(process.cwd(), file),
    line: text.slice(0, index).split('\n').length,
    link,
    reason,
  });
}

for (const file of walk(process.cwd())) {
  const text = readFileSync(file, 'utf8');

  for (const m of text.matchAll(
    /https:\/\/protocol\.dfos\.com(\/[A-Za-z0-9._/-]*)?(#[^\s)'"`\]]+)?/g,
  )) {
    const route = m[1] && m[1] !== '/' ? m[1].replace(/\/$/, '') : '/';
    const anchor = m[2]?.slice(1);
    const link = `protocol.dfos.com${route === '/' ? '/' : route}${anchor ? '#' + anchor : ''}`;

    if (!routes.has(route)) {
      report(file, m.index, text, link, 'no such page on the site');
      continue;
    }
    if (!anchor) continue;

    const source = markdown.get(route);
    if (!source) {
      const reason =
        `${route} builds its body in the page component, so its headings cannot be` +
        ' read from a file — link the page without a fragment';
      report(file, m.index, text, link, reason);
      continue;
    }
    if (!anchorsOf(source).has(anchor)) {
      report(
        file,
        m.index,
        text,
        link,
        `no such heading on ${route} (${relative(process.cwd(), source)})`,
      );
    }
  }

  // Relative markdown links: file existence only (see the header note).
  for (const m of text.matchAll(
    /\]\(((?:\.{1,2}\/|specs\/)[A-Za-z0-9._/-]+\.md)(?:#[^\s)]*)?\)/g,
  )) {
    const target = resolve(file, '..', m[1]);
    try {
      statSync(target);
    } catch {
      report(file, m.index, text, m[1], 'no such file in the repo');
    }
  }
}

if (offenders.length > 0) {
  console.error('Dead links into the served corpus found:\n');
  for (const o of offenders) {
    console.error(`  ${o.path}:${o.line}  →  ${o.link}`);
    console.error(`      ${o.reason}`);
  }
  console.error(
    '\nHeading anchors are slugged the way the site renders them' +
      '\n(packages/site-protocol/src/lib/renderSpec.ts). Open the target page,' +
      '\ncopy the anchor from its heading link, and cite that — or fix the page.',
  );
  process.exit(1);
}

console.log('heading anchors OK — every protocol.dfos.com link resolves to a page and a heading.');
