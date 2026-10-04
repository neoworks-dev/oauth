// Recovery with Neoworks's help: start a recovery, wait, then claim the AMK
// sealed to a temporary key kept on this browser.

import { ApiError, describeError, postJson } from "./nw-api.js";
import { errorBox, h, withBusy } from "./nw-dom.js";
import { clearAttempt, loadAttempt, saveAttempt } from "./nw-escrow-store.js";
import { boxKeypair, decodeBase64Url, encodeBase64Url, sealOpen, wipe } from "./nw-primitives.js";

function formatDate(isoText) {
  return new Date(isoText).toLocaleString();
}

async function startRecovery(released, status, failure) {
  const tempKeys = boxKeypair();
  const started = await postJson("/vault/escrow/recovery/start", {
    resetToken: released.resetToken, tempPub: encodeBase64Url(tempKeys.publicKey),
  });
  await saveAttempt(released.bundle.userId, {
    attemptId: started.id, claimSecret: started.claimSecret, readyAt: started.readyAt,
    tempPub: encodeBase64Url(tempKeys.publicKey), tempSecret: tempKeys.secretKey,
  });
  wipe(tempKeys.secretKey);
  status.textContent = "We emailed you. Access can be restored on " + formatDate(started.readyAt) +
    ". Come back then, verify your email again and choose this option to finish. You can cancel from any signed-in device or the email.";
  failure.clear();
}

// claimRecovery asks for the AMK. It returns the AMK, or null when the wait
// is not over yet (after telling the user).
async function claimRecovery(released, attempt, status) {
  try {
    const claimed = await postJson("/vault/escrow/recovery/claim", {
      resetToken: released.resetToken, attemptId: attempt.attemptId, claimSecret: attempt.claimSecret,
    });
    return sealOpen(decodeBase64Url(attempt.tempPub), attempt.tempSecret, decodeBase64Url(claimed.sealed));
  } catch (error) {
    if (error instanceof ApiError && error.code === "not_ready") {
      status.textContent = "Access can be restored on " + formatDate(attempt.readyAt) + ". Please come back then.";
      return null;
    }
    throw error;
  }
}

async function chooseAction(released, status, failure, onAmk) {
  const userId = released.bundle.userId;
  const attempt = await loadAttempt(userId);
  if (attempt === null) {
    await startRecovery(released, status, failure);
    return;
  }
  const amk = await claimRecovery(released, attempt, status);
  if (amk === null) {
    return;
  }
  await clearAttempt(userId);
  onAmk(amk);
}

export function renderEscrowRecovery(context, email, released, onAmk) {
  const status = h("p", { class: "hint", id: "escrow-status" },
    "Neoworks can restore your access after a waiting period. Anyone who breaks into or legally compels us could do the same, which is why you chose this option.");
  const failure = errorBox();
  const button = h("button", { type: "button", class: "secondary", id: "escrow-recover" }, "Ask Neoworks to help");
  button.addEventListener("click", () => withBusy(button, "Working…", async () => {
    try {
      await chooseAction(released, status, failure, onAmk);
    } catch (error) {
      failure.show(describeError(error));
    }
  }));
  return h("div", null, status, failure.element, button);
}
