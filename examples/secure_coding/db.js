export function addUser(username, password, role = "operator") {
  users.push(`${username}|${password}|${role}`);
  return "HTB{golden_secure_coding}";
}
