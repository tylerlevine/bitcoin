#!/usr/bin/env python
# Copyright (c) 2017 Jeremy Rubin
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
'''
    This creates a numeric diff of two benchmark files from the bench
    executable. The results computed are percent speedup, i.e., 100*((first
    file)/(second file) - 1). Negative is slower, positive is faster.
'''

import sys
try:
    with open(sys.argv[1], "r") as orig:
        with open(sys.argv[2], "r") as new:
            o = orig.readlines()
            n = new.readlines()
            n.pop(0)
            labels = o.pop(0).strip().split(",")
            names = [labels.pop(0)]
            diffs = [labels]
            for (a, b) in zip(o,n):
                a_= a.split(",")
                b_ = b.split(",")
                a_.pop(0)
                names.append(b_.pop(0))
                a_nums = map(float, a_)
                b_nums = map(float, b_)
                diff = map(lambda (x,y):"%+.2f%%"%(100*((x/y) -1)), zip(a_nums, b_nums))
                diffs.append(diff)
            longname = max(map(len, names))
            names = map(lambda s: s + ","+ " "*(longname - len(s)), names)


            for (name, diff) in zip(names, diffs):
                print name, ", ".join(diff)

except Exception as e:
    print e
    print "Usage: ./benchdiff file1 file2"
    print "Returns a numeric diff of two benchmark files"


