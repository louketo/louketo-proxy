# Louketo Community

Louketo Proxy is an Open Source adapter solution to protect non-Java modern Applications and Services.

## Building and working with the codebase

Details for building from source and working with the codebase are provided in the [building and working with the code base](docs/building.md) guide.

## Contributing to Louketo

Louketo is an Open Source community-driven project and we welcome contributions as well as feedback from the community.

We do have a few guidelines in place to help you be successful with your contribution.

Here's a quick checklist for a good PR, more details below:

1. [Louketo Mailing List](https://groups.google.com/forum/#!forum/louketo)
2. The issue number associated with the PR
3. One feature/change per PR
4. One commit per PR
5. PR rebased on master (`git rebase`, not `git pull`) 
6. Commit message including the GitHub issue number
7. No changes to code not directly related to your PR
8. Includes test
9. Includes documentation

Once you have submitted your PR please monitor it for comments/feedback. We reserve the right to close inactive PRs if
you do not respond within 2 weeks (bear in mind you can always open a new PR if it is closed due to inactivity).

Also, please remember that we do receive a fairly large amount of PRs and also have code to write ourselves, so we may
not be able to respond to your PR immediately. The best place to ping us is on the thread you started on the dev mailing list.

### Finding something to work on

If you would like to contribute to Louketo, but are not sure exactly what to work on, you can find a number of open
issues that are awaiting contributions in the 
[GitHub Issues](https://github.com/louketo/louketo-proxy/issues).

### Open a discussion on Louketo Mailing List

As Louketo is a community-driven project we require contributors to send a description of what they are planning to 
work on to the [Louketo Mailing List](https://groups.google.com/forum/#!forum/Louketo-dev).

We recommend starting the discussion prior to submitting your PR. Through the mailing list you can get valuable
feedback both from the core Louketo team as well as the wider community.

### Create an issue in GitHub Issues

Take your time to write a proper issue including a good summary and description. 

Remember this may be the first thing a reviewer of your PR will look at to get an idea of what you are proposing 
and it will also be used by the community in the future to find about what new features and enhancements are included in 
new releases.

### Implementing

Details for building from source and working with the codebase are provided in the 
[building and working with the code base](docs/building.md) guide.

Do not format or refactor code that is not directly related to your contribution. If you do this it will significantly
increase our effort in reviewing your PR. If you have a strong need to refactor code then submit a separate PR for the
refactoring.

### Documentation

We require contributions to include relevant documentation. Alongside your PR for code changes, prepare a PR to the [Louketo Documentation](https://github.com/Louketo/Louketo-documentation).

In the description of your PR include a link to the PR to [Louketo Documentation](https://github.com/Louketo/Louketo-documentation).

### Submitting your PR

When preparing your PR make sure you have a single commit and your branch is rebased on the master branch from the 
project repository.

This means use the `git rebase` command and not `git pull` when integrating changes from master to your branch. See
[Git Documentation](https://git-scm.com/book/en/v2/Git-Branching-Rebasing) for more details.

We require that you squash to a single commit. You can do this with the `git rebase -i HEAD~X` command where X
is the number of commits you want to squash. See the [Git Documentation](https://git-scm.com/book/en/v2/Git-Tools-Rewriting-History)
for more details.

The above helps us review your PR and also makes it easier for us to maintain the repository. It is also required by
our automatic merging process. 

We also require that the commit message is prefixed with the GitHub issue number (example commit message 
"My super cool new feature #9876").
