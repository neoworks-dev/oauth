// Shared page chrome for views.

import { clearElement, h } from "./nw-dom.js";

export function mountView(context, ...children) {
  clearElement(context.view);
  context.view.append(...children);
}

export function heading(title, subtitle) {
  const nodes = [h("h1", null, title)];
  if (subtitle) {
    nodes.push(h("p", { class: "subtitle" }, subtitle));
  }
  return nodes;
}

export function link(label, href, onNavigate) {
  return h("a", {
    href,
    onclick: (event) => {
      event.preventDefault();
      onNavigate(href);
    },
  }, label);
}
