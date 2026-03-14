import type { Context } from 'hono';
import { Hono } from 'hono';
import { cors } from 'hono/cors';
import documentEnvelope from '../../dfos-protocol/schemas/document-envelope.v1.json';
import post from '../../dfos-protocol/schemas/post.v1.json';
import profile from '../../dfos-protocol/schemas/profile.v1.json';

const app = new Hono();

// ── Schema Routes ──────────────────────────────────────────────────────────────

const schemas: Record<string, object> = {
  '/document-envelope/v1': documentEnvelope,
  '/post/v1': post,
  '/profile/v1': profile,
};

const SCHEMA_HEADERS = {
  'Content-Type': 'application/schema+json; charset=utf-8',
  'Cache-Control': 'public, max-age=31536000, immutable',
};

function serveSchema(c: Context) {
  const schema = schemas[c.req.path];
  if (!schema) return c.notFound();
  return c.text(JSON.stringify(schema, null, 2), 200, {
    ...SCHEMA_HEADERS,
    'Access-Control-Allow-Origin': '*',
  });
}

app.get('/document-envelope/v1', serveSchema);
app.get('/post/v1', serveSchema);
app.get('/profile/v1', serveSchema);

// CORS preflight for schema routes
app.options('/document-envelope/v1', cors());
app.options('/post/v1', cors());
app.options('/profile/v1', cors());

// ── Meta Routes ────────────────────────────────────────────────────────────────

app.get('/robots.txt', (c) => {
  return c.text(
    ['User-agent: *', 'Allow: /', '', 'Sitemap: https://schemas.dfos.com/sitemap.xml'].join('\n'),
  );
});

app.get('/sitemap.xml', (c) => {
  const urls = ['/', '/document-envelope/v1', '/post/v1', '/profile/v1'];
  const xml = [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">',
    ...urls.map(
      (url) =>
        `  <url><loc>https://schemas.dfos.com${url}</loc><changefreq>monthly</changefreq></url>`,
    ),
    '</urlset>',
  ].join('\n');
  return c.text(xml, 200, { 'Content-Type': 'application/xml; charset=utf-8' });
});

app.get('/llms.txt', (c) => {
  return c.text(
    [
      '# DFOS Content Schemas',
      '',
      '> JSON Schema definitions for DFOS protocol content types.',
      '',
      '## Schemas',
      '',
      '- [document-envelope/v1](https://schemas.dfos.com/document-envelope/v1): Standard wrapper for chain-committed content',
      '- [post/v1](https://schemas.dfos.com/post/v1): Posts, comments, and replies',
      '- [profile/v1](https://schemas.dfos.com/profile/v1): Identity profiles',
      '',
      '## Related',
      '',
      '- [Protocol Specification](https://protocol.dfos.com/spec): Full DFOS protocol spec',
      '- [npm Package](https://www.npmjs.com/package/@metalabel/dfos-protocol): @metalabel/dfos-protocol',
      '- [GitHub](https://github.com/metalabel/dfos): Source code',
    ].join('\n'),
  );
});

// ── Landing Page ───────────────────────────────────────────────────────────────

app.get('/', (c) => {
  return c.html(/* html */ `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DFOS Content Schemas</title>
<meta name="description" content="JSON Schema definitions for DFOS protocol content types. Document envelopes, posts, profiles.">
<meta name="robots" content="index, follow, max-snippet:-1">
<link rel="canonical" href="https://schemas.dfos.com/">
<link rel="icon" type="image/png" href="https://protocol.dfos.com/icon.png">
<link rel="apple-touch-icon" href="https://protocol.dfos.com/apple-touch-icon.png">
<meta property="og:type" content="website">
<meta property="og:title" content="DFOS Content Schemas">
<meta property="og:description" content="JSON Schema definitions for DFOS protocol content types.">
<meta property="og:url" content="https://schemas.dfos.com/">
<meta property="og:site_name" content="DFOS">
<meta property="og:image" content="https://protocol.dfos.com/og.png">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="DFOS Content Schemas">
<meta name="twitter:description" content="JSON Schema definitions for DFOS protocol content types.">
<meta name="twitter:image" content="https://protocol.dfos.com/og.png">
<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "WebSite",
  "name": "DFOS Content Schemas",
  "url": "https://schemas.dfos.com",
  "description": "JSON Schema definitions for DFOS protocol content types."
}
</script>
<style>
body { font-family: monospace; max-width: 60ch; margin: 2em auto; padding: 0 1em; line-height: 1.6; }
h1 { font-size: 1em; font-weight: bold; }
a { color: inherit; }
li { margin-bottom: 0.4em; }
hr { border: none; border-top: 1px solid #ccc; margin: 1.5em 0; }
small { color: #666; }
small a { color: #666; }
</style>
</head>
<body>
<h1>DFOS Content Schemas</h1>
<p>JSON Schema definitions for <a href="https://protocol.dfos.com">DFOS protocol</a> content types.</p>
<ul>
<li><a href="/document-envelope/v1">document-envelope/v1</a> &mdash; standard wrapper for chain-committed content</li>
<li><a href="/post/v1">post/v1</a> &mdash; posts, comments, and replies</li>
<li><a href="/profile/v1">profile/v1</a> &mdash; identity profiles</li>
</ul>
<hr>
<p><small><a href="https://protocol.dfos.com">Protocol</a> · <a href="https://github.com/metalabel/dfos">GitHub</a> · <a href="https://www.npmjs.com/package/@metalabel/dfos-protocol">npm</a> · <a href="https://dfos.com">dfos.com</a></small></p>
</body>
</html>`);
});

export default app;
