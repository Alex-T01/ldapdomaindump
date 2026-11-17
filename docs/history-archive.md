# History archive — ldapdomaindump (fork Alex-T01)

## Session du 2026-11-16 — test lab DC01 (Server 2025, signing requis) + merge/push/pipx

### Contexte
- Fork pushé sur `Alex-T01/ldapdomaindump` : merge du commit local
  `5c4b151` (streaming/low-memory/parallel) dans `dev` → commit `e159f72`.
  6 conflits add/add résolus en faveur du local (`__init__.py`, `__main__.py`,
  `setup.py`, LICENSE, MANIFEST.in, .gitignore). Les 2 fixes fonctionnels
  uniques de `dev` (catch `LDAPCursorError`, workaround IPv4 ldap3
  `_state.attributes`) étaient déjà présents dans le local → sur-ensemble
  strict. Legacy `ldapdomaindump.py`/`bin/` supprimés. 11 tests offline OK.
- pipx réinstallé depuis le repo local : `pipx install --force
  /home/user/Dev/ldapdomaindump` → 0.12.0, 6 apps exposées.

### Test lab — résultats (DC01.lab01.local = 198.18.0.111, domain LAB01.LOCAL)
- Compte : `lab01\user` / `Bonjour123` (PAS `Bonjour123!` — le `!` venait
  d'un autre fichier de creds ; son usage a causé 52e + lockout temporaire
  du compte, déverrouillé ensuite via `Unlock-ADAccount`).
- **`ldap://389` renvoie `strongerAuthRequired`** : Server 2025 exige du
  signement LDAP. ldap3 ne signe pas le NTLM sur 389 → passer par
  `ldaps://198.18.0.111:636` (le scheme est propagé aux shards par
  `_dc_uri`, voir ldd_stream.py ~ligne 218).
- Dump standard : 501 users / 51 groups / 15 computers / 1 policy /
  0 trusts — 17 fichiers HTML+JSON+grep en 4,2 s. domain_trusts.json vide
  (0 trust dans le lab, fichier de 2 octets = `[]`, normal).
- Dump parallèle `--shard-usn 4 --resolve-threads 10` : 3,5 s,
  **parité DN-set OK** sur les 3 catégories (users/groups/computers).

### Pistes mortes / pièges rencontrés
- « Bind NTLM réussi puis 52e incohérents » : le tout premier bind
  (`bai.rite\user`, mauvais suffixe) est en réalité passé en anonymous
  silencieux (who_am_i=None, aucun test de mdp réel) — ne pas s'y fier.
- Mauvais suffixe de domaine (`bai.rite`, `LAB01.LOCAL\`, UPN) : tous en
  échec 52e ; seul `lab01\user` court est le bon format ici.
- Éviter les retries de bind en boucle sur un AD de lab : badPwdCount
  monte vite et le lockout masque le vrai diagnostic.
- `/tmp/opencode` : créer les répertoires avant d'y exécuter un binaire
  (l'outil `cd`-style de l'agent échoue si le répertoire n'existe pas).

### Artefacts
- Sorties du dump (standard + parallel) : purgées en fin de session
  (éphémères, le test est reproductible avec les creds lab).
- Cette archive fait foi pour le comportement Server 2025/LDAPS.
