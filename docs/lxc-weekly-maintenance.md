# Maintenance hebdomadaire des LXC (optionnelle)

`pve-lxc-weekly` est un script local à exécuter sur un nœud Proxmox VE. Il ne dépend ni du wrapper SSH, ni de l’extension d’accès hôte, ni d’Hermes. Il n’installe pas de cron, ne met pas à jour l’hôte et ne démarre jamais un LXC arrêté.

## Installer et inspecter

Sur le nœud PVE, en tant que `root`, depuis un checkout de confiance, avec Python 3.11+ et l’outil `pct` de Proxmox :

```sh
install -m 0755 scripts/pve-lxc-weekly.py /usr/local/sbin/pve-lxc-weekly
if [ ! -e /etc/pve-lxc-weekly.json ] && [ ! -L /etc/pve-lxc-weekly.json ]; then
    install -m 0600 examples/pve-lxc-weekly.example.json /etc/pve-lxc-weekly.json
fi
/usr/local/sbin/pve-lxc-weekly --audit
```

La configuration et les journaux doivent rester privés et appartenir au compte qui exécute la tâche (normalement `root`). La commande `install` ci-dessus est pour une première installation : ne remplacez pas un fichier de configuration existant. `--audit` n’exécute aucune commande dans les invités et ne notifie pas. Il montre les LXC repérés et ce qui est exclu ou arrêté ; il ne simule pas les mises à jour de paquets.

Le défaut traite les paquets des LXC actifs, sans application autorisée. Ajoutez les VMID à ignorer à `exclude`, y compris ceux qui ne doivent jamais être mis à jour même si quelqu’un les démarre. Le script revalide l’état, l’absence de verrou et le nom de l’invité avant d’y intervenir. Sur un hôte contenant déjà une maintenance, évitez de programmer simultanément deux jobs de mise à jour.

## Tester avant de planifier

Sur un LXC de test en marche, remplacer `200` par son VMID. **Ce n’est pas un audit : des paquets peuvent être installés.**

```sh
/usr/local/sbin/pve-lxc-weekly --only 200 --phase system --no-notify
```

Debian, Ubuntu et Devuan utilisent un rafraîchissement strict d’APT suivi d’un `upgrade` **sans suppression de paquet**, avec vérification des versions installées. Un avertissement ou une erreur au rafraîchissement bloque l’installation, même sur un ancien APT qui renvoie `0`. Alpine utilise APK après simulation. Une distribution non gérée donne un avertissement, sans action. Une mise à jour de paquet peut redémarrer un service via ses propres scripts, même si le programme ne redémarre jamais un LXC.

Les transactions système et applicatives n’ont pas de délai global qui les tuerait en cours d’installation. Une commande bloquée peut donc retenir le verrou et empêcher le prochain passage. Les opérations qui ont leur propre délai (connexions APT, sondes Grafana, inventaire) le conservent. En cas d’interruption, vérifier l’état du gestionnaire de paquets (par exemple `dpkg --audit`) avant toute relance ; aucune réparation automatique n’est effectuée.

### Community Scripts : opt-in par LXC

Le profil applicatif est prévu pour **Grafana natif sur Alpine**. Le LXC doit déjà disposer du lanceur Community Scripts `/usr/bin/update` et répondre sur `http://127.0.0.1:3000/api/health` par défaut. Si Grafana écoute localement en HTTPS, ajouter `"health_scheme": "https"` au profil. La vérification du certificat est désactivée uniquement pour cette sonde sur l’adresse de boucle locale fixe, sans identifiants, proxy ni redirection. Le script vérifie le `slug`, le nom du LXC, le lanceur et l’état de l’API avant et après. Le profil ne modifie pas les réglages d’écoute et n’envoie aucune réponse aux menus.

Exemple de champ `apps` (VMID et nom d’hôte à adapter) :

```json
{
  "apps": {
    "200": {"name": "metrics-lxc", "slug": "grafana"}
  }
}
```

Ne remplacez que le champ `apps` de votre configuration par cette valeur. Pour un pilote applicatif sans étape système :

```sh
/usr/local/sbin/pve-lxc-weekly --only 200 --phase app
```

Le profil lance `PHS_SILENT=1 /usr/bin/update` dans le LXC. Le script Community Scripts installé peut télécharger du code **dans le LXC** ; le moteur PVE n’exécute aucun script téléchargé directement sur l’hôte. Un autre lanceur, un menu non prévu, un téléchargement en échec ou un délai dépassé demandent une intervention ; aucune relance ni réponse automatique n’est activée. Les autres applications ne sont pas mises à jour par cette phase.

### Notifications (facultatives)

Le rapport JSON et les journaux détaillés restent dans le répertoire privé `state_dir`, dans un sous-répertoire par exécution. Les notifications n’embarquent pas ces journaux. Pour activer Gotify, ajouter un objet `gotify` contenant `url` (URL complète de l’endpoint `/message` sans paramètres ni redirection) et `token` (jeton **d’application**, pas un jeton de lecture). Indiquer l’adresse HTTPS de son serveur. Configurer cette valeur directement sur le nœud, dans le fichier mode `0600` : jamais dans Git, le cron, les arguments CLI ou un rapport. Le rapport enregistre l’ID du message renvoyé par Gotify ; la réception sur un téléphone demande un test séparé.

Le champ `mail_to` est optionnel et nécessite `/usr/sbin/sendmail` fonctionnel. Il envoie un résumé en cas d’avertissement. `patchmon_report` est désactivé par défaut ; s’il est activé, le script appelle l’agent Patchmon existant après une phase système réussie.

### Rétention des rapports

Le programme ne purge pas les rapports. Sur PVE, on peut configurer `systemd-tmpfiles` pour nettoyer les anciens journaux, par exemple avec `/etc/tmpfiles.d/pve-lxc-weekly.conf` (adapter le chemin à `state_dir`) :

```text
d /var/log/pve-lxc-weekly 0700 root root 90d
x /var/log/pve-lxc-weekly/maintenance.lock - - - -
```

Le nettoyage dépend de `systemd-tmpfiles-clean.timer`. L’exclusion du verrou est indispensable pour éviter qu’un second lancement ne crée un nouveau fichier de verrou pendant un run actif.

### Horaire et retour arrière

Après le pilote et la vérification du rapport, ajouter **manuellement** une ligne à `crontab -e` en tant que `root`, par exemple le lundi à minuit dans le fuseau du nœud :

```cron
0 0 * * 1 PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin /usr/local/sbin/pve-lxc-weekly
```

Pour arrêter la maintenance, retirer uniquement la ligne ajoutée. Pour désinstaller le script, supprimer ensuite l’exécutable installé après avoir vérifié qu’aucun autre job ne l’utilise. Conserver ou archiver le fichier de configuration et les rapports selon vos besoins. Le programme ne touche pas aux jobs de sauvegarde.

### Codes de sortie

- `0` : opérations prévues réussies ou éléments non concernés ignorés, et pas d’erreur Gotify si configuré.
- `1` : un prérequis empêche le lancement (configuration, inventaire, verrou de maintenance, etc.).
- `2` : avertissement sur le déroulement ou échec de publication Gotify. Un `0` n’implique pas qu’un paquet a changé ; consulter `system` et `application` dans le rapport.

Lancer les tests locaux avec `python -m pytest -q tests/test_lxc_weekly.py`. Ils utilisent un `pct` simulé ; ils ne remplacent pas le test du cron complet sur un nœud réel.
