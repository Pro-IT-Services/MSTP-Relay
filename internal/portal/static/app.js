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

// suggestUsername returns a username for the given host name. step selects the style, so
// repeated clicks give different results. Output matches the server's [A-Za-z0-9._@+-]{1,64}.
function suggestUsername(name, step) {
  // Keep only as many whole words as fit in ~20 characters, so suffixes are never cut off.
  let w = nameWords(name);
  while (w.length > 1 && w.join("-").length > 20) w = w.slice(0, -1);
  if (w.length === 1) w = [w[0].slice(0, 20)];
  const nn = String(10 + randInt(90));
  if (w.length === 0) {
    return ADJECTIVES[randInt(ADJECTIVES.length)] + "-" + ANIMALS[randInt(ANIMALS.length)] + "-" + nn;
  }
  const last = w[w.length - 1];
  const initials = w.slice(0, -1).map((x) => x[0]).join("");
  const styles = [
    () => w.join("-"), //                          office-scanner
    () => w.join("."), //                          office.scanner
    () => (initials + last) + nn, //               oscanner47
    () => "svc-" + w.join("-"), //                 svc-office-scanner
    () => w[0] + "-" + nn, //                      office-47
    () => w.join("") + "-smtp", //                 officescanner-smtp
    () => w.join("-") + "-" + ANIMALS[randInt(ANIMALS.length)], // office-scanner-lynx
    () => "relay-" + (initials + last) + "-" + nn, // relay-oscanner-47
  ];
  return styles[step % styles.length]().slice(0, 32).replace(/[-.]+$/, "");
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
