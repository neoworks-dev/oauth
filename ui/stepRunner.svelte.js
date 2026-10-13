// The busy and error state of a screen that talks to the server, one step at a time.

import { describeError } from "$legacy/nw-api.js"

export function createStepRunner() {
  let isBusy = $state(false)
  let errorMessage = $state("")

  return {
    get isBusy() {
      return isBusy
    },
    get errorMessage() {
      return errorMessage
    },
    set errorMessage(message) {
      errorMessage = message
    },

    // Runs the action with the busy state on. A failure becomes the error message.
    async run(action, describeFailure = describeError) {
      errorMessage = ""
      isBusy = true
      try {
        await action()
      } catch (error) {
        errorMessage = describeFailure(error)
      } finally {
        isBusy = false
      }
    },
  }
}
