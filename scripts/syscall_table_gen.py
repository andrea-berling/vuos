#!/usr/bin/env python3
import sys
import os.path


def usage():
	print("{}: the input should be 'vu_syscalls.conf'".format(sys.argv[0]))

if len(sys.argv) < 2 or not os.path.isfile(sys.argv[1]):
	usage()
	sys.exit(1)

# Parse and output
header = '''
#include <syscall_defs.h>
#include <syscall_table.h>

/* Architecture INdependent table,
 * this is unique and stable for UMView reference */

/*This table has been autogenerated from vu_syscalls.conf */

'''
print(header)

cset = set()
wiset = set()
wdset = set()
woset = set()
vwset = set()

table = "struct syscall_tab_entry vu_syscall_table[] = {\n"
vtable = "struct vsyscall_tab_entry vvu_syscall_table[] = {\n"
ntable = "char *vu_syscall_names[] = {\n"
vntable = "char *vvu_syscall_names[] = {\n"
with open(sys.argv[1]) as f:
	for line in f:
		line = line.strip()
		if not line.startswith('#'):
			linesplit = line.split(':', maxsplit = 1)
			if len(linesplit) > 1:
				s, args = linesplit
				s = s.split(',')[0].strip()
				s = s.split('/')[0].strip()
				if s.startswith('-'):
					s = s[1:].strip()
					stag = "__VVU_" + s
					args = args.split(',')
					c = "choice_" + args[0].strip()
					w = "vw_" + args[1].strip()
					vtable += "\t[-{}] = {{{}, {}}},\n".format(stag, c, w)
					vntable += "\t[-{}] = \"{}\",\n".format(stag, s)
					cset.add(c)
					vwset.add(w)
				else:
					stag = "__VU_" + s
					args = args.split(',')
					while len(args) < 6:
						args.append("NULL")
					c = "choice_" + args[0].strip()
					win = "wi_" + args[1].strip()
					wd = "wd_" + args[2].strip()
					wout = "wo_" +args[3].strip()
					table += "\t[{}] = {{{}, {}, {}, {}}},\n".format(
							stag, c, win, wd, wout)
					ntable += "\t[{}] = \"{}\",\n".format(stag, s)
					cset.add(c)
					wiset.add(win)
					wdset.add(wd)
					woset.add(wout)
table += "};\n"
vtable += "};\n"
ntable += "};\n"
vntable += "};\n"

for f in sorted(cset):
	print("choicef_t {};".format(f))
for f in sorted(wiset):
	print("wrapf_t {};".format(f))
for f in sorted(wdset):
	print("wrapf_t {};".format(f))
for f in sorted(woset):
	print("wrapf_t {};".format(f))
for f in sorted(vwset):
	print("wrapf_t {};".format(f))
print()
print(table)
print(ntable)
print(vtable)
print(vntable)
