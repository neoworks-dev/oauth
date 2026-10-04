// Same-origin JSON calls to the vault server. The custom header is what the
// server's CSRF check looks for.

export class ApiError extends Error {
  constructor(status, code) {
    super(code);
    this.status = status;
    this.code = code;
  }
}

async function parseBody(response) {
  try {
    return await response.json();
  } catch (error) {
    return {};
  }
}

function encodeBody(body) {
  if (body === undefined) {
    return undefined;
  }
  return JSON.stringify(body);
}

function errorCode(payload) {
  if (payload.error) {
    return payload.error;
  }
  return "request_failed";
}

async function request(method, path, body) {
  const response = await fetch(path, {
    method,
    credentials: "same-origin",
    cache: "no-store",
    headers: { "Content-Type": "application/json", "X-NW-Vault": "1" },
    body: encodeBody(body),
  });
  const payload = await parseBody(response);
  if (!response.ok && response.status !== 202) {
    throw new ApiError(response.status, errorCode(payload));
  }
  return { status: response.status, body: payload };
}

export async function getJson(path) {
  return (await request("GET", path)).body;
}

export async function postJson(path, body) {
  if (body === undefined) {
    body = {};
  }
  return (await request("POST", path, body)).body;
}

export async function pollJson(path) {
  return request("GET", path);
}

// callApi calls the data API with the vault's own access token.
export async function callApi(apiUrl, method, path, body) {
  const token = await postJson("/vault/token");
  const response = await fetch(apiUrl + path, {
    method,
    headers: { Authorization: "Bearer " + token.access_token, "Content-Type": "application/json" },
    body: encodeBody(body),
  });
  const payload = await parseBody(response);
  if (!response.ok) {
    throw new ApiError(response.status, errorCode(payload));
  }
  return payload;
}

const ERROR_MESSAGES = {
  invalid_credentials: "Incorrect email or password.",
  rate_limited: "Too many attempts. Please wait a few minutes and try again.",
  device_revoked: "This browser was signed out of your account. Contact support or use another device.",
  email_taken: "An account with that email already exists.",
  code_incorrect: "That code is not correct.",
  code_expired: "That code has expired. Request a new one.",
  too_many_attempts: "Too many wrong codes. Request a new one.",
  email_not_verified: "Verify your email first.",
  bundle_version_conflict: "Your keys changed on another device. Reload and try again.",
  escrow_unavailable: "Key recovery help is not available right now.",
  escrow_failed: "The recovery service did not respond. Try again later.",
};

export function describeError(error) {
  if (error instanceof ApiError && ERROR_MESSAGES[error.code]) {
    return ERROR_MESSAGES[error.code];
  }
  return "Something went wrong. Please try again.";
}
