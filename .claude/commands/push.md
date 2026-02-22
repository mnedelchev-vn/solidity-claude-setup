## Task

This command is built to shorten the manual commands when pushing to Github.

Execute:
- `git status` will output all the current changes that are not pushed yet. We need this information to build proper commit message. In case that there is nothing to commit stop the task execution here.
- `git add -A`
- Build a commit message and pass it to `git commit -m '<COMMIT_MESSAGE>'`. The commit message shouldn't be longer than 50 symbols. In this message I'd like to include resume information of commit's changes to the repository.
- Last step is to push the commit to Github:
    - `git branch` will return info which is the current branch
    - `git push origin <BRANCH_NAME>` to perform the push