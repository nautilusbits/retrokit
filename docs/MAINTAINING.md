# Maintaining retro-kit

The primary repository is a self-hosted Gitea; GitHub is a public copy. Gitea's **push
mirror** (repository Settings -> Repository -> Mirror Settings, "sync when commits are
pushed") sends every branch and tag to GitHub with a fine-grained token (Contents and
Workflows: read and write, this repository only). The mirror pushes with force, so `main`
on GitHub is protected by a ruleset (no force pushes, no deletion): if GitHub ever has
commits Gitea does not, the sync fails visibly in the mirror settings instead of
overwriting them - bring them home as described below. Renew the token before it expires.

Alternative without a push mirror: `.gitea/workflows/github-mirror.yml` pushes `main` and tags
without force once an Actions runner and `GITHUB_MIRROR_REPO` / `GITHUB_MIRROR_TOKEN` exist.

## Publishing on GitHub (once)

1. Check the history: no game names, game code or personal data in any commit
   (`git log --all -p` against the blocklist; the author e-mail is part of every commit -
   rewrite it to a GitHub no-reply address first if it should not be public).
2. Create the empty GitHub repository (no README, no license - they come from Gitea).
3. GitHub -> Settings -> Branches: protect `main`, block force pushes and deletion.
4. Create a fine-grained GitHub token for that repository only: Contents read/write,
   Workflows read/write.
5. Gitea -> repository -> Settings -> Repository -> Mirror Settings: push mirror to the GitHub
   URL, username = GitHub user, password = the token, sync when commits are pushed;
   "Synchronize Now" to check. (Or the Actions workflow above.)
6. Make the GitHub repository public, add the ruleset for `main`, enable private
   vulnerability reporting (Settings -> Security).

## Pull requests from GitHub

Merge them in the primary repository, not on GitHub:

```
git fetch github pull/123/head:pr-123
git log --oneline main..pr-123        # review; python -m unittest discover -s tests
git merge --no-ff pr-123              # a merge (or fast-forward) keeps the PR's commits:
git push origin main                  # GitHub marks the PR merged when they reach main
```

After a squash or rebase GitHub cannot tell; close the PR with a link to the commit.

If a PR was merged on GitHub after all, the next mirror push fails. Bring it home:

```
git pull github main
git push origin main
```

## Releases

Tag in Gitea (`git tag -a v0.1.0 -m "retro-kit 0.1.0" && git push origin v0.1.0`); the tag
reaches GitHub through the workflow, then create the GitHub release from it.
