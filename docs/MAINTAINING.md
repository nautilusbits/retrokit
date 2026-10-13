# Maintaining retro-kit

The primary repository is a self-hosted Gitea; GitHub is a public copy that receives every
push to `main` and every tag from Gitea (`.gitea/workflows/github-mirror.yml`). Pushes are
never forced, so nothing on GitHub is overwritten; a push that GitHub rejects means the two
have diverged and has to be resolved by hand.

## Publishing on GitHub (once)

1. Check the history: no game names, game code or personal data in any commit
   (`git log --all -p` against the blocklist; the author e-mail is part of every commit -
   rewrite it to a GitHub no-reply address first if it should not be public).
2. Create the empty GitHub repository (no README, no license - they come from Gitea).
3. GitHub -> Settings -> Branches: protect `main`, block force pushes and deletion.
4. Create a fine-grained GitHub token for that repository only: Contents read/write,
   Workflows read/write.
5. Gitea -> repository -> Settings -> Actions: variable `GITHUB_MIRROR_REPO` = `owner/name`,
   secret `GITHUB_MIRROR_TOKEN` = the token. An Actions runner (act_runner) must be
   registered for the repository, the user or the instance.
6. Push anything to `main` (or re-run the last workflow): the job pushes `main`; push the
   tags once with `git push origin --tags`.

Without a runner, push to both directly instead: `git push origin main && git push github main`.

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
