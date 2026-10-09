# proxmox-containers-admin

Wrapper SSH restreint + skill d’usage pour administrer des LXC/VM Proxmox sans exposer un shell root complet sur l’hôte.

Le projet contient deux briques complémentaires :
- un **wrapper shell** installé sur l’hôte Proxmox, exécuté via une clé SSH forcée ;
- un **skill OpenClaw/Codex** qui documente comment l’utiliser proprement côté agent.

## À quoi ça sert

L’objectif est de pouvoir faire des opérations d’admin courantes sur des guests Proxmox :
- lister les LXC/VM ;
- vérifier leur état ;
- lire leur configuration ;
- exécuter des commandes dans un guest ;
- transférer un fichier vers ou depuis un LXC ;
- effectuer des actions d’alimentation seulement si on le souhaite explicitement.

Le tout sans donner un shell libre sur le nœud Proxmox par défaut.

## Extension optionnelle : accès temporaire à l’hôte

Une extension Python/systemd ajoute deux modes approuvés par mot de passe :
SAFE (catalogue fermé de 22 diagnostics) et FULL (shell root volontairement accordé).
Durée par défaut 15 minutes, maximum 30 minutes ; mot de passe à la connexion,
puis approbation explicite sans seconde saisie dans une session de 15 minutes.
Gotify ne transporte qu’un lien non autorisant. Une session volée peut autoriser.
Interface HTTPS sur PVE sous compte non root, broker privilégié local et sockets
Unix avec SO_PEERCRED. Aucune dépendance WebAuthn/TOTP, aucun signup/reset public.

Sans installation explicite, les commandes hôte sont refusées et les commandes
invités restent inchangées. Installation sans démarrage automatique, venv dédié,
bootstrap opérateur via getpass, désinstallation préservant le wrapper existant.
FULL n’est pas un confinement de root : root peut contourner la supervision.

### Installation pour un nouvel utilisateur

- Le wrapper LXC/VM reste utilisable seul ; l’extension hôte est entièrement optionnelle.
- Prérequis : Python >=3.11 avec venv/pip, systemd, compte SSH agent dédié et proxy HTTPS de confiance.
- Installer depuis un checkout relu sur PVE, créer la configuration avec les UID locaux et l’origine HTTPS propre au déploiement, puis initialiser le mot de passe localement.
- Gotify est facultatif ; ses secrets restent sur PVE, hors Git et hors accès de l’agent.
- Le backend écoute en loopback par défaut. Un proxy distant exige une restriction réseau à son IP exacte.
- Aucun service n’est démarré ou activé automatiquement. L’opérateur valide le parcours avant d’activer le démarrage au boot.
- La désinstallation conserve le wrapper, le compte, la configuration et les secrets ; la mise à jour exige une sauvegarde et une réinstallation contrôlée.

Le [guide d’installation](docs/temporary-host-access.md#installation-operator-on-the-destination-pve-not-run-by-an-agent) fournit les commandes, permissions, vérifications et limites ; il ne suppose aucun domaine, UID ou secret du homelab de l’auteur.

- [Installation, protocole et catalogue](docs/temporary-host-access.md)
- [Modèle de menace et limites](docs/security.md)
- [Tests automatisés et acceptation réelle séparée](docs/testing.md)

Vérifications locales (pas de production) :

```bash
python3 -m venv .venv
.venv/bin/python -m pip install setuptools==84.0.0 wheel==0.48.0
.venv/bin/python -m pip install --no-build-isolation -c requirements.lock -e '.[test]'
install -d -m 0700 "$HOME/.proxmox-host-access-tests"
TMPDIR="$HOME/.proxmox-host-access-tests" .venv/bin/python -m pytest -q
.venv/bin/python -m ruff check host_access tests
bash -n scripts/proxmox-guest-wrapper.sh scripts/install-host-access.sh scripts/uninstall-host-access.sh
.venv/bin/python -m build --wheel --no-isolation
```

L’E2E local utilise de vrais sockets Unix et HTTPS, un backend d’exécution injecté
pour les tests et un récepteur Gotify local. Il ne valide pas le téléphone, Gotify
réel, PVE, Traefik, ni les cgroups systemd de production.

## Ce qui est publié dans ce dépôt

Arborescence minimale recommandée :

```text
proxmox-containers-admin/
├── .gitignore
├── README.md
├── SKILL.md
├── examples/
│   ├── authorized_keys.example
│   └── proxmox-guest-wrapper.sudoers
└── scripts/
    └── proxmox-guest-wrapper.sh
```

Contenu :
- `.gitignore` : ménage de base pour un petit dépôt shell/doc ;
- `README.md` : présentation, installation, sécurité, tests ;
- `SKILL.md` : consignes d’usage pour un agent ;
- `examples/proxmox-guest-wrapper.sudoers` : exemple de règle `sudoers` dédiée ;
- `examples/authorized_keys.example` : exemple de clé SSH forcée sur le wrapper ;
- `scripts/proxmox-guest-wrapper.sh` : wrapper à installer sur l’hôte Proxmox.

## Principe de fonctionnement

Le compte SSH dédié n’a pas de shell utile. Sa clé publique est forcée avec :

```text
command="sudo /usr/local/sbin/proxmox-guest-wrapper",...
```

Le wrapper lit `SSH_ORIGINAL_COMMAND`, n’accepte qu’un petit vocabulaire d’actions, puis traduit chaque action vers une commande Proxmox sous-jacente (`pct`, `qm`, `qm guest exec`, `pct pull`, `pct push`, etc.).

Le modèle de sécurité est :
- **hôte Proxmox restreint**
- **guest ciblé administrable**

## Actions exposées

### Inventaire
- `list-lxc` -> `pct list`
- `list-vm` -> `qm list`

### État
- `lxc-status <vmid>` -> `pct status <vmid>`
- `vm-status <vmid>` -> `qm status <vmid>`
- `vm-agent-ping <vmid>` -> `qm agent <vmid> ping`

### Configuration
- `lxc-config <vmid>` -> `pct config <vmid>`
- `vm-config <vmid>` -> `qm config <vmid>`

### Exécution dans le guest
- `lxc-shell <vmid> -- <commande>` -> `pct exec <vmid> -- sh -c "<commande>"`
- `vm-shell <vmid> -- <commande>` -> `qm guest exec <vmid> -- sh -c "<commande>"`
- `lxc-shell-stdin <vmid>` -> `pct exec <vmid> -- sh -s`
- `vm-shell-stdin <vmid>` -> `qm guest exec <vmid> --pass-stdin 1 -- sh -s`

### Transfert de fichiers LXC
- `lxc-pull <vmid> <guest-path>` -> `pct pull <vmid> <guest-path> <tempfile>`
- `lxc-push <vmid> <guest-path>` -> `pct push <vmid> <tempfile> <guest-path>`

### Alimentation
- `lxc-power <vmid> <start|stop|shutdown|reboot>` -> `pct <verb> <vmid>`
- `vm-power <vmid> <start|stop|shutdown|reboot|reset>` -> `qm <verb> <vmid>`

## Exemples d’usage

```bash
ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" "list-lxc"
ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" "lxc-status 117"
ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" "lxc-config 117"
ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" "lxc-shell 117 -- hostname"
ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" "lxc-shell 117 -- systemctl status nginx --no-pager"
ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" "lxc-shell 117 -- journalctl -u nginx -n 100 --no-pager | tail -20"
ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" "lxc-pull 117 /etc/app/config.yaml" > config.yaml
ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" "lxc-push 117 /etc/app/config.yaml" < config.yaml
```

Les chemins guest avec espaces sont acceptés pour `lxc-pull` et `lxc-push`.

Pour les opérations multi-lignes ou plus complexes, utiliser les variantes `*-stdin` :

```bash
ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" "lxc-shell-stdin 117" <<'EOF'
set -eu
hostname
df -h
systemctl status nginx --no-pager
EOF
```

## Limites connues

Le wrapper est volontairement simple. Il y a quelques points à connaître :
- il ne parse **qu’une seule action wrapper** par connexion SSH ;
- si on chaîne plusieurs actions wrapper dans une seule commande SSH, seule la première passe par `SSH_ORIGINAL_COMMAND` ;
- les suivantes sont alors exécutées dans le shell du guest et échouent typiquement avec `sh: 1: lxc-shell: not found` ;
- `vm-shell-stdin` nécessite une version de `qm guest exec` supportant `--pass-stdin 1` ; sans cette option, la commande peut retourner un succès sans exécuter le script reçu ;
- le wrapper extrait le champ JSON `exitcode` renvoyé par `qm guest exec` afin de propager l’échec du processus invité au client SSH ;
- toujours vérifier un effet concret côté VM après une exécution par stdin.

En pratique :
- utiliser **un appel SSH par action wrapper** ;
- garder `lxc-shell` et `vm-shell` pour les commandes simples ;
- préférer `lxc-shell-stdin` ou `vm-shell-stdin` pour les opérations longues ou multi-lignes ;
- garder le push d’un script temporaire comme solution de repli quand il faut aussi transférer des fichiers.

## Installation côté Proxmox

### 1. Créer l’utilisateur SSH dédié

```bash
useradd -m -s /bin/bash proxmox-agent
install -d -m 700 -o proxmox-agent -g proxmox-agent /home/proxmox-agent/.ssh
```

### 2. Installer le wrapper

Copier `scripts/proxmox-guest-wrapper.sh` sur l’hôte puis :

```bash
install -m 755 -o root -g root proxmox-guest-wrapper.sh /usr/local/sbin/proxmox-guest-wrapper
```

### 3. Autoriser uniquement ce wrapper via sudo

Créer `/etc/sudoers.d/proxmox-guest-wrapper` :

```sudoers
Defaults:proxmox-agent !requiretty
Defaults:proxmox-agent env_keep += "SSH_ORIGINAL_COMMAND"
Defaults!/usr/local/sbin/proxmox-guest-wrapper secure_path=/usr/sbin:/usr/bin:/sbin:/bin

proxmox-agent ALL=(root) NOPASSWD: /usr/local/sbin/proxmox-guest-wrapper
```

Vérification :

```bash
visudo -cf /etc/sudoers.d/proxmox-guest-wrapper
```

### 4. Forcer la clé SSH sur le wrapper

Créer une clé dédiée côté client :

```bash
ssh-keygen -t ed25519 -f ~/.ssh/proxmox-agent -C "proxmox-agent"
```

Puis mettre dans `/home/proxmox-agent/.ssh/authorized_keys` :

```text
command="sudo /usr/local/sbin/proxmox-guest-wrapper",no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding ssh-ed25519 AAAA...cle... proxmox-agent
```

Et finir avec :

```bash
chown -R proxmox-agent:proxmox-agent /home/proxmox-agent/.ssh
chmod 700 /home/proxmox-agent/.ssh
chmod 600 /home/proxmox-agent/.ssh/authorized_keys
```

## Variables côté client / agent

```bash
export PROXMOX_HOST=pve.local
export PROXMOX_SSH_USER=proxmox-agent
```

## Sécurité

Pourquoi ce wrapper est raisonnablement sûr :
- il n’utilise pas `eval` sur `SSH_ORIGINAL_COMMAND` ;
- il n’ouvre pas de shell libre sur l’hôte ;
- il n’expose qu’un jeu d’actions borné ;
- les transferts LXC utilisent un fichier temporaire interne au wrapper, supprimé automatiquement ;
- l’environnement `SSH_ORIGINAL_COMMAND` est explicitement conservé via `sudoers`.

Ce qu’il faut garder en tête :
- `lxc-shell`, `vm-shell` et `lxc-push` donnent beaucoup de liberté **dans le guest ciblé** ;
- ce n’est donc pas un sandbox d’admin guest, seulement un garde-fou pour ne pas exposer l’hôte Proxmox lui-même.

## Tests rapides

### Test local sur l’hôte

```bash
SSH_ORIGINAL_COMMAND='list-lxc' /usr/local/sbin/proxmox-guest-wrapper
SSH_ORIGINAL_COMMAND='lxc-status 117' /usr/local/sbin/proxmox-guest-wrapper
SSH_ORIGINAL_COMMAND='lxc-shell 117 -- hostname' /usr/local/sbin/proxmox-guest-wrapper
SSH_ORIGINAL_COMMAND='lxc-shell 117 -- journalctl -u nginx -n 20 --no-pager | tail -5' /usr/local/sbin/proxmox-guest-wrapper
```

### Test distant

```bash
ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" "list-lxc"
ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" "lxc-status 117"
ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" "lxc-config 117"
ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" "lxc-shell 117 -- hostname"
ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" "lxc-pull 117 /etc/app/config.yaml" > config.yaml
ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" "lxc-push 117 /etc/app/config.yaml" < config.yaml
```
