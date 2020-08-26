#!/bin/sh

make clean
perl Makefile.PL && make && make test \
&& ./script/00-bench-xs.t
