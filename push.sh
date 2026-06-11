#!/bin/bash
cd /Users/jmaker/Desktop/hacker/bingo
rm -rf .git
git init
git config user.name "bingook"
git config user.email "bingook@users.noreply.github.com"
git add .
export GIT_AUTHOR_NAME="bingook"
export GIT_AUTHOR_EMAIL="bingook@users.noreply.github.com"
export GIT_COMMITTER_NAME="bingook"
export GIT_COMMITTER_EMAIL="bingook@users.noreply.github.com"
git commit -m "feat: bingo v1.0.0"
git log --format="%an <%ae>" -1
echo "===완료==="
