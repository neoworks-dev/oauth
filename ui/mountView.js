// Shows a Svelte component in the page's view area, replacing whatever was there.
// The router calls cancelOnNavigate when the user leaves; a component can also unmount
// itself earlier through the unmountView prop.

import { mount, unmount } from "svelte"
import { clearElement } from "$legacy/nw-dom.js"

export function showComponent(context, component, extraProps) {
  clearElement(context.view)

  const mountedComponent = mount(component, {
    target: context.view,
    props: { context, unmountView, ...extraProps },
  })

  function unmountView() {
    unmount(mountedComponent)
    context.cancelOnNavigate = null
  }

  context.cancelOnNavigate = unmountView
}
