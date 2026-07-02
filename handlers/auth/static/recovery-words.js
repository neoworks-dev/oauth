// Maps each byte (0-255) to a word, so the recovery key can be
// written down or read aloud instead of copying a base64 blob.
var RECOVERY_WORDLIST = [
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

function concatBytes(a, b) {
  var out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

function bytesToWords(bytes) {
  var words = [];
  for (var i = 0; i < bytes.length; i++) {
    words.push(RECOVERY_WORDLIST[bytes[i]]);
  }
  return words;
}

// Inverse of bytesToWords. Throws if a word isn't in the wordlist.
function wordsToBytes(words) {
  var bytes = new Uint8Array(words.length);
  for (var i = 0; i < words.length; i++) {
    var index = RECOVERY_WORDLIST.indexOf(words[i].toLowerCase());
    if (index === -1) {
      throw new Error("Unknown recovery word: " + words[i]);
    }
    bytes[i] = index;
  }
  return bytes;
}

function renderRecoveryWords(container, words) {
  container.innerHTML = "";
  for (var i = 0; i < words.length; i++) {
    var item = document.createElement("div");
    var index = document.createElement("span");
    index.className = "word-index";
    index.textContent = (i + 1) + ".";
    item.appendChild(index);
    item.appendChild(document.createTextNode(words[i]));
    container.appendChild(item);
  }
}

function downloadRecoveryKey(words) {
  var lines = words.map(function (word, i) {
    return (i + 1) + ". " + word;
  });
  var content =
    "NeoWorks recovery key\n" +
    "Keep this safe — it's the only way to recover your account if you forget your password.\n\n" +
    lines.join("\n") +
    "\n";
  var blob = new Blob([content], { type: "text/plain" });
  var url = URL.createObjectURL(blob);
  var link = document.createElement("a");
  link.href = url;
  link.download = "neoworks-recovery-key.txt";
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}
