## Task

The purpose of this command is to shorten the manual terminal commands when pushing to GitHub.

Execute:
- `git status` will output all the current changes that are not pushed yet. We need this information to build proper commit message. In case that there is nothing to commit stop the task execution here.
- `git add -A` will prepare files to be included in the upcoming commit.
- Build a commit message and pass it to `git commit -m <COMMIT_MESSAGE>`. The commit message shouldn't be longer than 50 symbols. The message should include resume information of the changes about to be pushed to the repository.
- Last step is to push the commit to GitHub:
    - `git branch` will return info which is the current branch
    - `git push origin <BRANCH_NAME>` to perform the push