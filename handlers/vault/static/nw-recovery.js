// Recovery key words: every byte of the 32 byte recovery entropy maps to one of
// 256 words, so the key can be written down or read aloud.

const RECOVERY_WORDLIST = [
"airport", "alligator", "almond", "amber", "anchor", "antelope", "apple", "archery",
"attic", "avalanche", "badger", "baker", "bakery", "balcony", "banana", "basket",
"bear", "beaver", "bedroom", "beetle", "biscuit", "blanket", "blizzard", "bottle",
"boulder", "breeze", "bridge", "bronze", "bucket", "buffalo", "builder", "butter",
"button", "cabin", "camel", "canary", "candle", "canoe", "canyon", "captain",
"carpenter", "carpet", "castle", "cellar", "chameleon", "chapel", "charcoal", "cherry",
"chimney", "chipmunk", "cinnamon", "clarinet", "cliff", "closet", "cobra", "comet",
"compass", "compassion", "copper", "coral", "corridor", "cottage", "courtyard", "crayon",
"crimson", "crocodile", "crystal", "curtain", "cushion", "dancer", "desert", "diamond",
"discus", "doctor", "dolphin", "doorway", "drought", "drum", "eagle", "earthquake",
"eclipse", "elevator", "emerald", "escalator", "falcon", "farmer", "fencing", "ferret",
"flamingo", "forest", "fountain", "garden", "gecko", "ginger", "glacier", "glider",
"golden", "granite", "grape", "gravel", "guitar", "hallway", "hammer", "hamster",
"hanger", "harbor", "hedgehog", "highway", "hockey", "honey", "horizon", "hurdle",
"hurricane", "iguana", "indigo", "island", "ivory", "javelin", "jungle", "kayak",
"kitchen", "koala", "ladder", "lagoon", "lantern", "lemon", "library", "lighthouse",
"lightning", "limestone", "lion", "llama", "magenta", "magnet", "mango", "mantis",
"marathon", "marble", "market", "meadow", "melon", "meteor", "mirror", "monsoon",
"monument", "moonlight", "moose", "mountain", "muffin", "museum", "needle", "noodle",
"nurse", "oasis", "obsidian", "orchard", "ostrich", "otter", "paddle", "painter",
"pancake", "panda", "pantry", "parrot", "pasture", "pavement", "peach", "peacock",
"pebble", "pelican", "penguin", "pepper", "piano", "pickle", "pillow", "pilot",
"plateau", "plumber", "prairie", "pretzel", "pumpkin", "python", "quartz", "rabbit",
"railway", "rainbow", "raven", "ribbon", "rocket", "rowboat", "ruby", "sailor",
"salmon", "sapphire", "satellite", "sausage", "scarlet", "sculptor", "shark", "shovel",
"sidewalk", "silver", "singer", "soccer", "sparrow", "spider", "sprinter", "squirrel",
"stadium", "staircase", "starlight", "station", "statue", "sticker", "sunshine", "teacher",
"telescope", "temple", "tennis", "terrace", "theater", "thunder", "tiger", "topaz",
"tornado", "toucan", "trout", "trumpet", "tundra", "tunnel", "turquoise", "turtle",
"twilight", "valley", "vanilla", "vineyard", "violet", "violin", "viper", "volcano",
"wallpaper", "walnut", "walrus", "wardrobe", "whale", "whirlpool", "whistle", "wildfire",
"windmill", "window", "wolf", "woodpecker", "wrench", "writer", "zebra", "zipper",
];

export function bytesToWords(bytes) {
  return Array.from(bytes, (byte) => RECOVERY_WORDLIST[byte]);
}

// wordsToBytes is the inverse of bytesToWords. It throws on an unknown word.
export function wordsToBytes(words) {
  const bytes = new Uint8Array(words.length);
  words.forEach((word, position) => {
    const index = RECOVERY_WORDLIST.indexOf(word.trim().toLowerCase());
    if (index === -1) {
      throw new Error("Unknown recovery word: " + word);
    }
    bytes[position] = index;
  });
  return bytes;
}

// parseRecoveryWords accepts the words separated by spaces, commas or lines.
export function parseRecoveryWords(text) {
  const words = text.split(/[\s,]+/).filter((word) => word.length > 0);
  return wordsToBytes(words);
}

export function downloadRecoveryKey(words) {
  const lines = words.map((word, position) => (position + 1) + ". " + word);
  const content = "Neoworks recovery key\n" +
    "Keep this safe. It is the only way to recover your account if you forget your password.\n\n" +
    lines.join("\n") + "\n";
  const url = URL.createObjectURL(new Blob([content], { type: "text/plain" }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = "neoworks-recovery-key.txt";
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}
