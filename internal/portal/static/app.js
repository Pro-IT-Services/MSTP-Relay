// Ask for confirmation on forms marked with data-confirm (e.g. delete buttons).
document.addEventListener("submit", (e) => {
  const msg = e.target.dataset && e.target.dataset.confirm;
  if (msg && !window.confirm(msg)) e.preventDefault();
});

// "Generate" buttons: fill the target password field with a random password and show it.
document.addEventListener("click", (e) => {
  const id = e.target.dataset && e.target.dataset.generate;
  if (!id) return;
  const field = document.getElementById(id);
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
  const bytes = crypto.getRandomValues(new Uint8Array(20));
  field.value = Array.from(bytes, (b) => chars[b % chars.length]).join("");
  field.type = "text";
  field.select();
});

// --- SMTP username suggestions ---

const ADJECTIVES = ["brisk", "calm", "clever", "quiet", "rapid", "steady", "bright", "bold", "swift", "keen", "solid", "nimble"];
const ANIMALS = ["otter", "falcon", "lynx", "heron", "badger", "marten", "osprey", "bison", "raven", "ibex", "puffin", "gecko"];

function randInt(n) {
  return crypto.getRandomValues(new Uint32Array(1))[0] % n;
}

// Words of a host name, lower-case ASCII: "Café Scanner – 2nd floor" -> ["cafe", "scanner", "2nd", "floor"].
function nameWords(name) {
  return name
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "") // strip accents
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
}

// fitWords shortens a word list until it fits max characters when joined with one separator
// each. It keeps what identifies the device: the first word, the last word and codes containing
// digits. Plain words in the middle are dropped first (longest first); letters are trimmed only
// when nothing else is left to drop.
function fitWords(words, max) {
  const w = words.slice();
  const len = () => w.join("-").length;
  const isCode = (x) => /\d/.test(x);
  while (len() > max) {
    let drop = -1;
    for (let i = 1; i < w.length - 1; i++) {
      if (!isCode(w[i]) && (drop < 0 || w[i].length > w[drop].length)) drop = i;
    }
    if (drop >= 0) {
      w.splice(drop, 1);
      continue;
    }
    let trim = -1;
    for (let i = 0; i < w.length; i++) {
      if (!isCode(w[i]) && w[i].length > 4 && (trim < 0 || w[i].length > w[trim].length)) trim = i;
    }
    if (trim >= 0) w[trim] = w[trim].slice(0, -1);
    else if (w.length > 2) w.splice(Math.floor(w.length / 2), 1);
    else w[w.length - 1] = w[w.length - 1].slice(0, -1);
  }
  return w;
}

// uniq drops repeated words, so short names don't produce "printer-printer".
function uniq(words) {
  return words.filter((x, i) => words.indexOf(x) === i);
}

// suggestUsername returns a username for the given host name. step selects the style, so
// repeated clicks give different results. Every style draws on the whole name: all words where
// they fit, otherwise the parts that identify the device (first word, codes with digits, last
// words). Output matches the server's [A-Za-z0-9._@+-]{1,64}.
function suggestUsername(name, step) {
  const w = nameWords(name);
  const nn = String(10 + randInt(90));
  if (w.length === 0) {
    return ADJECTIVES[randInt(ADJECTIVES.length)] + "-" + ANIMALS[randInt(ANIMALS.length)] + "-" + nn;
  }
  const first = w[0];
  const last = w[w.length - 1];
  const codes = w.filter((x) => /\d/.test(x)); // model numbers, room codes
  const initials = w.slice(0, -1).map((x) => x[0]).join("");
  // Examples for the host name "Office Scanner X200 Room 3b East":
  const styles = [
    () => fitWords(w, 32).join("-"), //                           office-scanner-x200-room-3b-east
    () => uniq([first, ...w.slice(-2)]).join("-"), //             office-3b-east
    () => (codes.length ? uniq([...codes, last]) : fitWords(w, 32)).join(codes.length ? "-" : "."), // x200-3b-east
    () => (initials ? initials + "-" : "") + last + nn, //         osxr3-east47
    () => "svc-" + uniq([first, last]).join("-"), //              svc-office-east
    () => uniq([last, ...w.slice(0, 2)]).join("-"), //            east-office-scanner
    () => fitWords(uniq([first, ...codes, last]), 26).join("-") + "-smtp", // office-x200-3b-east-smtp
    () => uniq([first, last]).join("-") + "-" + ANIMALS[randInt(ANIMALS.length)], // office-east-lynx
  ];
  return styles[step % styles.length]().slice(0, 40).replace(/[-.]+$/, "");
}

document.addEventListener("click", (e) => {
  const id = e.target.dataset && e.target.dataset.generateUser;
  if (!id) return;
  const field = document.getElementById(id);
  const nameField = field.form && field.form.elements["name"];
  const name = nameField ? nameField.value : "";
  let step = Number(e.target.dataset.step || 0);
  let value = suggestUsername(name, step++);
  for (let i = 0; i < 8 && value === field.value; i++) value = suggestUsername(name, step++); // never repeat the current one
  e.target.dataset.step = step;
  field.value = value;
  field.select();
});
