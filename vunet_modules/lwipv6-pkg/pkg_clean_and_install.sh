#!/bin/zsh
tar zcf lwipv6-1.5.tar.gz ../lwipv6
rm -rf *.xz pkg src
makepkg -i
