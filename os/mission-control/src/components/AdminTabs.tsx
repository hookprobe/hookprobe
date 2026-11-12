/**
 * AdminTabs — the Administration tab strip (wireframe boards Admin / AdminConfig / AdminShell): the three admin pages
 * reach each other in one click, instead of Configuration and Shell losing the admin navigation.
 */
import { type Component, For } from 'solid-js';

const TABS: [string, string][] = [['/admin/identity', 'Settings'], ['/admin/config', 'Configuration and keys'], ['/admin/shell', 'Shell']];

const AdminTabs: Component<{ current: string }> = (props) => (
  <nav class="tabs" aria-label="Administration pages">
    <For each={TABS}>{([href, label]) => (
      <a class="tab" href={href} aria-current={props.current === href ? 'page' : undefined}
        style={{ display: 'inline-flex', 'align-items': 'center', 'text-decoration': 'none' }}>{label}</a>
    )}</For>
  </nav>
);

export default AdminTabs;
