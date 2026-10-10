# Outils d'historique Codex / Claude Code

Deux scripts pour retrouver un fil Codex et pour mettre les transcripts à l'abri
de la purge automatique. Tout est local : rien n'est envoyé nulle part.

## Pourquoi

- L'historique **local** (Codex CLI, Claude Code CLI/Desktop) et l'historique
  **cloud** (claude.ai/code) sont deux stockages distincts. Rien ne remonte du
  local vers le cloud : un fil importé n'apparaîtra jamais dans la barre
  latérale cloud, seul son groupe s'y synchronise, vide.
- Les transcripts Claude Code (`~/.claude/projects/<projet>/<session>.jsonl`)
  sont **supprimés** au-delà de `cleanupPeriodDays` (30 jours par défaut), sur
  l'âge du fichier. Un import qui préserve les dates d'origine est donc
  immédiatement candidat au balayage.

## `codex-resolve.sh` — où est passé ce fil ?

```bash
tools/codex-resolve.sh codex://threads/01a0486a-e232-7bc2-8f38-f447129bb778
tools/codex-resolve.sh 01a0486a-e232-7bc2-8f38-f447129bb778 --deep
tools/codex-resolve.sh <uuid> --also /Volumes/Backup/codex
```

Les identifiants de fil Codex sont des **UUIDv7** : leurs 48 premiers bits sont
un horodatage en millisecondes. Le script le décode, en déduit le dossier de
rollout attendu (`~/.codex/sessions/AAAA/MM/JJ/`, essayé en heure locale *et* en
UTC), puis cherche par nom de fichier et par contenu dans `~/.codex`, dans
`~/.claude/projects`, et où tu lui demandes.

| Verdict | Signification | Code |
|---|---|---|
| `INTACT` | Le fil est toujours dans Codex — c'est l'import qui l'a laissé de côté. | 0 |
| `IMPORT SEUL` | Parti de Codex, mais la copie importée existe. L'URI `codex://` est morte, le contenu non. | 0 |
| `AILLEURS` | Trouvé hors des emplacements standard. | 0 |
| `INTROUVABLE` | Purgé, né dans le Codex cloud (aucun fichier local), ou créé sur une autre machine. | 1 |

## `codex-backup.sh` — archiver avant la purge

```bash
tools/codex-backup.sh --dry-run        # ce qui serait archivé, sans rien écrire
tools/codex-backup.sh                  # archive dans ~/codex-claude-backups
tools/codex-backup.sh /Volumes/SSD/bk  # ailleurs
tools/codex-backup.sh --keep 10        # + rotation : garde les 10 plus récentes
```

Produit `codex-claude-AAAAMMJJ-HHMMSS.tar.gz` contenant `~/.codex/sessions`,
`~/.claude/projects` et un `index.tsv` à la racine :

```
source  uuid  mtime  age_jours  taille  chemin
```

L'archive est relue (`tar -tzf`) après écriture. Le script signale combien de
transcripts dépassent 30 jours. **Sans `--keep`, il ne supprime rien.**

⚠️ Les transcripts contiennent des échanges bruts : clés d'API, jetons et code
privé peuvent s'y trouver. Garde les archives hors de tout dépôt Git — la
`.gitignore` à la racine les exclut déjà par précaution.

## Variables d'environnement

| Variable | Défaut | Rôle |
|---|---|---|
| `CODEX_HOME` | `$HOME/.codex` | racine Codex |
| `CLAUDE_CONFIG_DIR` | `$HOME/.claude` | racine Claude Code (même variable que Claude Code) |
| `BACKUP_DIR` | `$HOME/codex-claude-backups` | destination par défaut des archives |

## Compatibilité

bash 3.2 (celui de macOS) : pas de tableaux associatifs ni de `mapfile`. Les
différences GNU/BSD sur `date` et `stat` sont gérées par détection. Testé sous
Linux sur fixtures couvrant les quatre verdicts, la rotation, les sources
absentes et les arguments invalides.
