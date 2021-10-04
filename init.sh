#!/bin/bash
#ssh git@ptmk.sy.gs new-repo leldap.git
git init
git submodule add https://github.com/xscorp/Burpee.git
git branch -M master
git remote add all git@github.com:MKesenheimer/leldap.git
git remote set-url --add --push all git@github.com:MKesenheimer/leldap.git
git remote set-url --add --push all git@ptmk.sy.gs:remotes/leldap.git
git remote set-url --add --push origin git@ptmk.sy.gs:remotes/leldap.git

# add and push to root
#git commit -am "Commit message"
#git push origin master

# add and push to all
#git commit -am "Commit message"
#git push origin all
