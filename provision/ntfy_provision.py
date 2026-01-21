#!/usr/bin/env python3
import argparse
import os
import re
import secrets
import string
import subprocess
import sys

try:
    import yaml  # pip install pyyaml
except ImportError:
    print("ERROR: Falta PyYAML. Instalá con: pip install pyyaml", file=sys.stderr)
    sys.exit(2)

PERM_MAP = {
    "ro": "read-only",
    "read": "read-only",
    "read-only": "read-only",
    "wo": "write-only",
    "write": "write-only",
    "write-only": "write-only",
    "rw": "rw",
    "deny": "deny-all",
    "deny-all": "deny-all",
}

def run(cmd, env=None, check=True):
    return subprocess.run(cmd, text=True, capture_output=True, env=env, check=check)

def load_env_file(path):
    if not path or not os.path.exists(path):
        return {}
    data = {}
    with open(path, "r", encoding="utf-8") as f:
        for ln in f:
            ln = ln.strip()
            if not ln or ln.startswith("#") or "=" not in ln:
                continue
            k, v = ln.split("=", 1)
            data[k.strip()] = v.strip()
    return data

def write_env_file(path, data):
    if not path:
        return
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        for k in sorted(data.keys()):
            f.write(f"{k}={data[k]}\n")
    os.chmod(tmp_path, 0o600)
    os.replace(tmp_path, path)

def gen_password(length=32):
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))

def ntfy_base(cfg):
    mode = cfg.get("mode", "docker")
    if mode == "docker":
        c = cfg.get("container")
        if not c:
            raise SystemExit("ERROR: mode=docker requiere 'container' en el YAML")
        return ["docker", "exec", "-i", c, "ntfy"]
    if mode == "local":
        return ["ntfy"]
    raise SystemExit("ERROR: mode debe ser 'docker' o 'local'")

def list_users(cfg):
    base = ntfy_base(cfg)
    p = run(base + ["user", "list"])
    users = set()
    for ln in p.stdout.splitlines():
        ln = ln.strip()
        if not ln or ln.lower().startswith("user"):
            continue
        users.add(ln.split()[0])
    return users

def ensure_user(cfg, existing_users, username, role, password):
    if username in existing_users:
        return False

    if not password:
        raise SystemExit(f"ERROR: Usuario '{username}' no existe y no se proveyó password/passwordEnv.")

    env = os.environ.copy()
    env["NTFY_PASSWORD"] = password  # evita prompt interactivo
    base = ntfy_base(cfg)
    run(base + ["user", "add", f"--role={role}", username], env=env)
    return True

def resolve_password(user_cfg, user_exists, secrets_env):
    password = user_cfg.get("password")
    if password:
        return password, False

    password_env = user_cfg.get("passwordEnv")
    if not password_env:
        return None, False

    env_val = os.environ.get(password_env)
    if env_val:
        if password_env in secrets_env and secrets_env[password_env] != env_val:
            raise SystemExit(f"ERROR: {password_env} difiere de {password_env} en secrets.env")
        return env_val, False

    if password_env in secrets_env:
        return secrets_env[password_env], False

    if user_exists:
        return None, False

    new_pw = gen_password()
    secrets_env[password_env] = new_pw
    return new_pw, True

def normalize_perm(p):
    key = (p or "").strip().lower()
    if key not in PERM_MAP:
        raise SystemExit(f"ERROR: Permiso inválido '{p}'. Usá rw/read-only/write-only/deny-all.")
    return PERM_MAP[key]

def access_dump(cfg, username):
    base = ntfy_base(cfg)
    p = run(base + ["access", username])
    return [ln.strip() for ln in p.stdout.splitlines() if ln.strip()]

def has_rule(lines, topic, perm):
    # Match tolerante: topic + perm en la misma línea
    rx = re.compile(rf"(^|\s){re.escape(topic)}(\s|$).*({re.escape(perm)})", re.IGNORECASE)
    return any(rx.search(ln) for ln in lines)

def ensure_access(cfg, username, topic, perm):
    perm_n = normalize_perm(perm)
    lines = access_dump(cfg, username)
    if has_rule(lines, topic, perm_n):
        return False
    base = ntfy_base(cfg)
    run(base + ["access", username, topic, perm_n])
    return True

def token_list(cfg, username):
    base = ntfy_base(cfg)
    p = run(base + ["token", "list", username])
    toks = []
    for ln in p.stdout.splitlines():
        ln = ln.strip()
        if not ln:
            continue
        m = re.search(r"(tk_[A-Za-z0-9]+)", ln)
        if m:
            toks.append(m.group(1))
    return toks

def ensure_tokens(cfg, username, ensure_count):
    base = ntfy_base(cfg)
    existing = token_list(cfg, username)
    created = []
    if len(existing) >= ensure_count:
        return created

    needed = ensure_count - len(existing)
    for _ in range(needed):
        p = run(base + ["token", "add", username])
        m = re.search(r"(tk_[A-Za-z0-9]+)", p.stdout)
        created.append(m.group(1) if m else "<token_creado_no_detectado>")
    return created

def merge_access_rules(*rule_lists):
    out = []
    for rules in rule_lists:
        if not rules:
            continue
        if not isinstance(rules, list):
            raise SystemExit("ERROR: access debe ser lista de {topic, perm}")
        out.extend(rules)
    return out

def merge_tokens_cfg(*token_cfgs):
    ensure = 0
    for tc in token_cfgs:
        if not tc:
            continue
        if not isinstance(tc, dict):
            raise SystemExit("ERROR: tokens debe ser un objeto {ensureCount: N}")
        ensure = max(ensure, int(tc.get("ensureCount", 0) or 0))
    return {"ensureCount": ensure}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("yaml_file")
    ap.add_argument("--mode", choices=["local", "docker"], help="Override mode from YAML")
    args = ap.parse_args()

    with open(args.yaml_file, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}
    if args.mode:
        cfg["mode"] = args.mode

    templates = cfg.get("templates", {}) or {}
    users = cfg.get("users", []) or []
    if not isinstance(users, list):
        raise SystemExit("ERROR: 'users' debe ser una lista")

    secrets_path = cfg.get("secretsFile", "out/secrets.env")
    secrets_env = load_env_file(secrets_path)
    secrets_dirty = False

    print("== ntfy provision (idempotent) ==")
    created_tokens_report = []
    existing_users = list_users(cfg)

    for u in users:
        username = u.get("username")
        if not username:
            raise SystemExit("ERROR: Cada user requiere 'username'")
        role = (u.get("role") or "user").strip()

        user_exists = username in existing_users
        password, generated = resolve_password(u, user_exists, secrets_env)
        if generated:
            secrets_dirty = True

        created = ensure_user(cfg, existing_users, username, role, password)
        print(f"[user] {username}: {'CREATED' if created else 'exists'} (role={role})")
        if created:
            existing_users.add(username)

        # Templates
        applied = u.get("applyTemplates", []) or []
        if not isinstance(applied, list):
            raise SystemExit(f"ERROR: applyTemplates de '{username}' debe ser lista")

        tpl_access = []
        tpl_tokens = []
        for tname in applied:
            t = templates.get(tname)
            if t is None:
                raise SystemExit(f"ERROR: Template '{tname}' no existe (usuario '{username}')")
            tpl_access.append(t.get("access", []))
            tpl_tokens.append(t.get("tokens", {}))

        # Merge access (templates + user)
        access_rules = merge_access_rules(*tpl_access, u.get("access", []))
        for r in access_rules:
            topic = r.get("topic")
            perm = r.get("perm")
            if not topic or not perm:
                raise SystemExit(f"ERROR: regla access inválida en '{username}' (requiere topic y perm)")
            changed = ensure_access(cfg, username, topic, perm)
            print(f"  [acl] {topic} -> {normalize_perm(perm)}: {'set' if changed else 'ok'}")

        # Merge tokens (max ensureCount)
        tokens_cfg = merge_tokens_cfg(*tpl_tokens, u.get("tokens", {}))
        ensure_count = int(tokens_cfg.get("ensureCount", 0) or 0)
        if ensure_count > 0:
            new_tokens = ensure_tokens(cfg, username, ensure_count)
            if new_tokens:
                created_tokens_report.append((username, new_tokens))
                print(f"  [token] created {len(new_tokens)} token(s)")
            else:
                print(f"  [token] ok (>= {ensure_count})")

    if created_tokens_report:
        print("\n== Newly created tokens (guardar en un secreto seguro) ==")
        for user, toks in created_tokens_report:
            for t in toks:
                print(f"{user}: {t}")

    if secrets_dirty:
        write_env_file(secrets_path, secrets_env)
        print(f"\n== Passwords guardadas en {secrets_path} (chmod 600) ==")

if __name__ == "__main__":
    main()
