import GithubSlugger from 'github-slugger';
import { Marked, type Tokens } from 'marked';
import { codeToHtml } from 'shiki';

export interface TocEntry {
  id: string;
  text: string;
  level: number;
}

export interface RenderedSpec {
  html: string;
  toc: TocEntry[];
}

/**
 * Syntax-highlight theme harmonized to the site palette. The green is never
 * desaturated — keywords and function names stay phosphor green; strings and
 * comments fall to the teal family; literals and identifiers are body white.
 * No off-brand rainbow colors. (See global.css: "the tension IS the brand".)
 */
const dfosTheme = {
  name: 'dfos',
  type: 'dark' as const,
  colors: {
    'editor.background': '#060606',
    'editor.foreground': '#adbdb8',
  },
  settings: [
    { settings: { foreground: '#adbdb8' } },
    {
      scope: ['comment', 'punctuation.definition.comment'],
      settings: { foreground: '#7a8e88', fontStyle: 'italic' },
    },
    {
      scope: [
        'keyword',
        'storage',
        'storage.type',
        'storage.modifier',
        'keyword.control',
        'keyword.operator.new',
        'variable.language',
        'entity.name.tag',
      ],
      settings: { foreground: '#00ff09' },
    },
    {
      scope: ['entity.name.function', 'support.function', 'meta.function-call.generic'],
      settings: { foreground: '#00ff09' },
    },
    {
      scope: ['string', 'string.quoted', 'constant.other.symbol', 'meta.attribute'],
      settings: { foreground: '#adbdb8' },
    },
    {
      scope: ['constant.numeric', 'constant.language', 'constant.language.boolean'],
      settings: { foreground: '#ffffff' },
    },
    {
      scope: ['variable', 'meta.object-literal.key', 'support.type.property-name'],
      settings: { foreground: '#ffffff' },
    },
    {
      scope: ['entity.name.type', 'support.type', 'support.class', 'entity.name.class'],
      settings: { foreground: '#adbdb8' },
    },
  ],
};

function escapeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

async function highlight(code: string, lang?: string): Promise<string> {
  if (!lang) return `<pre class="shiki"><code>${escapeHtml(code)}</code></pre>`;
  try {
    return await codeToHtml(code, { lang, theme: dfosTheme });
  } catch {
    // Unknown / unbundled grammar (e.g. abnf) — degrade to plain escaped text.
    return `<pre class="shiki"><code>${escapeHtml(code)}</code></pre>`;
  }
}

// Local spec links in the markdown source → site routes. Union of every form
// that appears across the specs (./FOO.md, ../dfos-protocol/FOO.md, legacy
// RELAY.md). Each is a no-op when its pattern is absent, so applying the full
// set to every page is safe.
const LINK_REWRITES: Array<[RegExp, string]> = [
  [/href="(?:\.\/|\.\.\/dfos-protocol\/)PROTOCOL\.md"/g, 'href="/spec"'],
  [/href="(?:\.\/|\.\.\/dfos-protocol\/)DID-METHOD\.md"/g, 'href="/did-method"'],
  [/href="(?:\.\/|\.\.\/dfos-protocol\/)CONTENT-MODEL\.md"/g, 'href="/content-model"'],
  [/href="(?:\.\/WEB-RELAY|\.\/RELAY|\.\.\/dfos-web-relay\/RELAY)\.md"/g, 'href="/web-relay"'],
  [/href="\.\/DOCUMENT-GATEWAY\.md"/g, 'href="/document-gateway"'],
  [/href="\.\/CREDENTIALS\.md"/g, 'href="/credentials"'],
  [/href="\.\/SIWD\.md"/g, 'href="/siwd"'],
  [/href="\.\/THREAT-MODEL\.md"/g, 'href="/threat-model"'],
  [/href="\.\/CONFORMANCE\.md"/g, 'href="/conformance"'],
  // SECURITY.md lives at the repo root (not a site route); point the rendered
  // link at GitHub so it resolves on the published site instead of 404ing.
  [/href="\.\.\/SECURITY\.md"/g, 'href="https://github.com/metalabel/dfos/blob/main/SECURITY.md"'],
];

/**
 * Render a spec markdown document to HTML for the site. Single source of truth
 * for every markdown-backed page: Shiki-highlighted code blocks (wrapped with a
 * copy button), deduplicated GitHub-style heading anchors, a collected TOC,
 * scroll-wrapped tables, and local-link rewriting.
 */
export async function renderSpec(markdown: string): Promise<RenderedSpec> {
  const slugger = new GithubSlugger();
  const toc: TocEntry[] = [];
  const highlighted = new WeakMap<Tokens.Code, string>();

  const marked = new Marked({
    async: true,
    async walkTokens(token) {
      if (token.type === 'code') {
        const code = token as Tokens.Code;
        highlighted.set(code, await highlight(code.text, code.lang));
      }
    },
    renderer: {
      code(token: Tokens.Code) {
        const inner =
          highlighted.get(token) ??
          `<pre class="shiki"><code>${escapeHtml(token.text)}</code></pre>`;
        return `<div class="code-wrap"><button class="code-copy" aria-label="Copy code">copy</button>${inner}</div>`;
      },
      heading(token: Tokens.Heading) {
        const inlineHtml = this.parser.parseInline(token.tokens);
        const plain = inlineHtml.replace(/<[^>]*>/g, '');
        const id = slugger.slug(plain);
        toc.push({ id, text: plain, level: token.depth });
        return `<h${token.depth} id="${id}"><a href="#${id}" class="anchor" aria-hidden="true">#</a>${inlineHtml}</h${token.depth}>`;
      },
      del(token: Tokens.Del) {
        // GFM reads a single "~" (e.g. "~3×") as strikethrough; in the specs it
        // means "approximately". Restore the literal tilde instead of <del>.
        return `~${this.parser.parseInline(token.tokens)}`;
      },
    },
  });

  let html = (await marked.parse(markdown)) as string;

  // Wrap tables for horizontal scroll on narrow viewports.
  html = html
    .replace(/<table>/g, '<div class="table-wrap"><table>')
    .replace(/<\/table>/g, '</table></div>');

  for (const [pattern, replacement] of LINK_REWRITES) {
    html = html.replace(pattern, replacement);
  }

  return { html, toc };
}
