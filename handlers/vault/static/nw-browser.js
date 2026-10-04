// Describes this browser for the device list.

const BROWSERS = [
  [/Edg\//, "Edge"],
  [/OPR\//, "Opera"],
  [/Firefox\//, "Firefox"],
  [/Chrome\//, "Chrome"],
  [/Safari\//, "Safari"],
];

const PLATFORMS = [
  [/Android/, "Android"],
  [/iPhone|iPad/, "iOS"],
  [/Windows/, "Windows"],
  [/Mac OS X/, "macOS"],
  [/Linux/, "Linux"],
];

function firstMatch(table, text, fallback) {
  for (const [pattern, name] of table) {
    if (pattern.test(text)) {
      return name;
    }
  }
  return fallback;
}

export function describeBrowser() {
  const agent = navigator.userAgent;
  return firstMatch(BROWSERS, agent, "Browser") + " on " + firstMatch(PLATFORMS, agent, "this device");
}
