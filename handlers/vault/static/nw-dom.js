// Minimal DOM construction. Content is only ever set through textContent and
// attributes, never HTML strings, so the page works under Trusted Types.

function applyAttribute(element, name, value) {
  if (value === null || value === undefined || value === false) {
    return;
  }
  if (name === "class") {
    element.className = value;
    return;
  }
  if (name.startsWith("on") && typeof value === "function") {
    element.addEventListener(name.slice(2), value);
    return;
  }
  if (value === true) {
    element.setAttribute(name, "");
    return;
  }
  element.setAttribute(name, String(value));
}

function applyAttributes(element, attributes) {
  for (const [name, value] of Object.entries(attributes)) {
    applyAttribute(element, name, value);
  }
}

export function h(tag, attributes, ...children) {
  const element = document.createElement(tag);
  if (attributes) {
    applyAttributes(element, attributes);
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) {
      continue;
    }
    element.append(child);
  }
  return element;
}

export function clearElement(element) {
  element.replaceChildren();
}

export function setText(element, text) {
  element.textContent = text;
}

export function setVisible(element, visible) {
  element.hidden = !visible;
}

// field builds a labelled input row.
export function field(label, inputAttributes) {
  const input = h("input", inputAttributes);
  const row = h("div", { class: "field" }, h("label", { for: inputAttributes.id }, label), input);
  return { row, input };
}

export function errorBox() {
  const box = h("p", { class: "error", role: "alert" });
  box.hidden = true;
  return {
    element: box,
    show(message) {
      box.textContent = message;
      box.hidden = false;
    },
    clear() {
      box.hidden = true;
    },
  };
}

// busy disables a button and swaps its label while an async action runs.
export async function withBusy(button, busyLabel, action) {
  const idleLabel = button.textContent;
  button.disabled = true;
  button.textContent = busyLabel;
  try {
    return await action();
  } finally {
    button.disabled = false;
    button.textContent = idleLabel;
  }
}
