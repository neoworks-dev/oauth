// Entry of the views bundle. The router in app.js calls these render functions.

import { showComponent } from "./mountView.js"
import CancelRecovery from "./CancelRecovery.svelte"
import Login from "./Login.svelte"
import Recover from "./Recover.svelte"
import Signup from "./Signup.svelte"

export { renderRecoveryKeyConfirmation } from "./recoveryKey.js"

export function renderLogin(context, { onDone }) {
  showComponent(context, Login, { onDone })
}

export function renderSignup(context, { onDone }) {
  showComponent(context, Signup, { onDone })
}

export function renderRecover(context) {
  showComponent(context, Recover, {})
}

export function renderCancelRecovery(context) {
  showComponent(context, CancelRecovery, {})
}
