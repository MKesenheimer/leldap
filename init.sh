#!/bin/bash
#ssh git@ptmk.sy.gs new-repo leldap.git
git init
git submodule add https://github.com/xscorp/Burpee.git
git branch -M master

# remote: all
git remote add all git@github.com:MKesenheimer/leldap.git
git remote set-url --add --push all git@github.com:MKesenheimer/leldap.git
git remote set-url --add --push all git@ptmk.sy.gs:remotes/leldap.git

# remote: origin
git remote add origin git@ptmk.sy.gs:remotes/leldap.git
git remote set-url --add --push origin git@ptmk.sy.gs:remotes/leldap.git

# add and push to root
#git add ...
#git commit -m "Commit message"
#git push origin master

# add and push to all
#git add ...
#git commit -m "Commit message"
#git push all master
