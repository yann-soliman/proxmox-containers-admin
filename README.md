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

Le tout sans donner un shell libre sur le nœud Proxmox.

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
- `lxc-shell <vmid> -- <commande>` -> `pct exec <vmid> -- sh -lc "<commande>"`
- `vm-shell <vmid> -- <commande>` -> `qm guest exec <vmid> -- sh -lc "<commande>"`

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

## Limites connues

Le wrapper est volontairement simple. Il y a quelques points à connaître :
- il ne parse **qu’une seule action wrapper** par connexion SSH ;
- si on chaîne plusieurs actions wrapper dans une seule commande SSH, seule la première passe par `SSH_ORIGINAL_COMMAND` ;
- les suivantes sont alors exécutées dans le shell du guest et échouent typiquement avec `sh: 1: lxc-shell: not found` ;
- pour les opérations multi-étapes, il est souvent plus fiable de pousser un script temporaire dans le guest plutôt que d’empiler des one-liners complexes.

En pratique :
- utiliser **un appel SSH par action wrapper** ;
- garder `lxc-shell` pour les commandes simples ;
- préférer un script temporaire pour les opérations longues ou multi-lignes.

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
