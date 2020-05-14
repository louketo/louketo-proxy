# Release process

## Before doing a release

* Make sure that all the issues in the milestones are resolved
* Make sure CI is passing

## Drafting a new release

The release process was automated to release builds based on the Git tag when a new draft release is created.

### Steps

1. Visit https://github.com/louketo/louketo-proxy/releases/new
2. Choose a new tag version based on [Semantic Versioning 2.0.0](https://semver.org/) and pick the target branch.
3. Choose the release title and add a proper description
4. Publish the release

The release process should be triggered by GitHub actions and once it's finished, all the binaries should be available in the release page. See the video below:

[![Release demo](http://img.youtube.com/vi/OkDd91L6GuQ/0.jpg)](http://www.youtube.com/watch?v=OkDd91L6GuQ "Release demo")


