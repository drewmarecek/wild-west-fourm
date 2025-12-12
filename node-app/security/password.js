const argon2 = require("argon2");

function validatePasswordStrength(pw) {
  if (typeof pw !== "string") return "Password required";
  if (pw.length < 12) return "Password must be at least 12 characters";
  if (!/[A-Z]/.test(pw)) return "Password must include an uppercase letter";
  if (!/[a-z]/.test(pw)) return "Password must include a lowercase letter";
  if (!/[0-9]/.test(pw)) return "Password must include a number";
  if (!/[^A-Za-z0-9]/.test(pw)) return "Password must include a symbol";
  return null;
}

async function hashPassword(pw) {
  return argon2.hash(pw, { type: argon2.argon2id });
}

async function verifyPassword(hash, pw) {
  return argon2.verify(hash, pw);
}

module.exports = { validatePasswordStrength, hashPassword, verifyPassword };
