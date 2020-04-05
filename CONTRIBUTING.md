## Contribution Guide

## Welcome Aboard

Thank you for taking interest in contributing to kube-hunter!  
This guide will walk you through the development process of kube-hunter.  

## Setting Up

kube-hunter is written in Python 3 and supports versions 3.6 and above.  
You'll probably want to create a virtual environment for your local project.  
Once you got your project and IDE set up, you can `make dev-deps` and start contributing!  
You may also install a pre-commit hook to take care of linting - `pre-commit install`.  

## Issues

- Feel free to open issues for any reason as long as you make it clear if this issue is about a bug/feature/hunter/question/comment.
- Please spend a small amount of time giving due diligence to the issue tracker. Your issue might be a duplicate. If it is, please add your comment to the existing issue.
- Remember users might be searching for your issue in the future, so please give it a meaningful title to help others.
- The issue should clearly explain the reason for opening, the proposal if you have any, and any relevant technical information. 

## Pull Requests

1. Every Pull Request should have an associated Issue unless you are fixing a trivial documentation issue.
1. Your PR is more likely to be accepted if it focuses on just one change.
1. Describe what the PR does. There's no convention enforced, but please try to be concise and descriptive. Treat the PR description as a commit message. Titles that start with "fix"/"add"/"improve"/"remove" are good examples.
1. Please add the associated Issue in the PR description.
1. There's no need to add or tag reviewers.
1. If a reviewer commented on your code or asked for changes, please remember to mark the discussion as resolved after you address it. PRs with unresolved issues should not be merged (even if the comment is unclear or requires no action from your side).
1. Please include a comment with the results before and after your change.
1. Your PR is more likely to be accepted if it includes tests (We have not historically been very strict about tests, but we would like to improve this!).

## Hunters

If you are contributing a new Hunter:
1. When you open an issue to present the Hunter, please specify which `Vulnerability` classes you plan to add.
1. A maintainer will assign each `Vulnerability` a VID for you to include in your Hunter code.
1. Please add a KB article to `/docs/kb/` explaining the vulnerability and suggesting remediation steps. Look at other articles for examples.
1. Please adhere to the following types convention: Use `Hunter` class to report vulnerabilities, `ActiveHunter` if your Hunter might change the state of the cluster, and `Discovery` for scanning the cluster (all are descendants of `HunterBase`). Also, use the `Vulnerability` class to report findings, and `Service` to report a discovery to be used by a hunter (both are descendants of `Event`, refrain from using `Event` directly).
