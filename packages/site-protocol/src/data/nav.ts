// Single source of truth for site navigation.
//
// Every nav surface renders from this one array — the global header (Base.astro),
// the landing hero header (index.astro), the landing closing-nav (index.astro),
// and the doc footer (Footer.astro). Before this existed, those four lists were
// hand-maintained and had drifted apart (different membership, different order);
// driving them all from here means they can never disagree again.
//
// The global header renders only the `primary` tier with terse `shortLabel`s.
// Footers render the full list with full `label`s. Order below is the canonical
// site order (understand → spec docs → use it → reference → external).

export interface NavLink {
  href: string;
  /** Full label — used in the footer and the landing closing-nav. */
  label: string;
  /** Terse label for the compact global header; falls back to `label`. */
  shortLabel?: string;
  /** `primary` links form the global-header spine; every link appears in footers. */
  tier: 'primary' | 'secondary';
  /** Offsite destination (GitHub, dfos.com). */
  external?: boolean;
}

export const navLinks: NavLink[] = [
  { href: '/', label: 'Home', tier: 'secondary' },
  { href: '/overview', label: 'Why', tier: 'primary' },
  { href: '/spec', label: 'Specification', shortLabel: 'Spec', tier: 'primary' },
  { href: '/did-method', label: 'DID Method', tier: 'secondary' },
  { href: '/content-model', label: 'Content Model', tier: 'secondary' },
  { href: '/credentials', label: 'Credentials', tier: 'secondary' },
  { href: '/siwd', label: 'Sign In With DFOS', tier: 'secondary' },
  { href: '/web-relay', label: 'Web Relay', shortLabel: 'Relay', tier: 'primary' },
  { href: '/document-gateway', label: 'Document Gateway', tier: 'secondary' },
  { href: '/cli', label: 'CLI', tier: 'primary' },
  { href: '/deploy', label: 'Deploy', tier: 'secondary' },
  { href: '/skill', label: 'Skill', tier: 'primary' },
  { href: '/threat-model', label: 'Threat Model', tier: 'secondary' },
  { href: '/conformance', label: 'Conformance', tier: 'secondary' },
  { href: '/faq', label: 'FAQ', tier: 'primary' },
  { href: 'https://github.com/metalabel/dfos', label: 'GitHub', tier: 'primary', external: true },
  { href: 'https://dfos.com', label: 'dfos.com', tier: 'secondary', external: true },
];

/** The global-header spine: primary tier, rendered with terse labels. */
export const primaryNav = navLinks.filter((link) => link.tier === 'primary');

/** A link's compact header label. */
export const headerLabel = (link: NavLink): string => link.shortLabel ?? link.label;
