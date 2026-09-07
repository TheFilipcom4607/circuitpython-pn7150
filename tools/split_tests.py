"""Split the on-device suite into chunks that each fit in RP2040 RAM.

CircuitPython compiles source into RAM at import, and the driver plus the whole
suite no longer fits. Sections (each `print("--- ...")` block) are packed
greedily into parts under a source-size budget; every part carries the same
prelude - the imports, the check helpers, and the shared fixtures - and
reports its own tally.
"""
import io
import sys

BUDGET = 4200          # bytes of section source per part, before minifying

src = io.open(sys.argv[1], encoding="utf-8").read()
out_dir = sys.argv[2]

first = src.index("\nt = mk(TECH_NFC_A")
prelude = src[:first].replace(
    'print("--- UID parsing, all four technologies ---")\n', "")
body = src[first:].replace(
    'print()\nprint("%d passed, %d failed" % (passed, failed))', "")

# Cut into sections on the banner lines, keeping the banner with its section.
marks = [0]
idx = body.find('\nprint("--- ')
while idx != -1:
    marks.append(idx + 1)
    idx = body.find('\nprint("--- ', idx + 1)
marks.append(len(body))
sections = [body[marks[i]:marks[i + 1]] for i in range(len(marks) - 1)]

parts, current = [], ""
for section in sections:
    if current and len(current) + len(section) > BUDGET:
        parts.append(current)
        current = section
    else:
        current += section
if current:
    parts.append(current)

summary = '\nprint()\nprint("%d passed, %d failed" % (passed, failed))\n'
for i, part in enumerate(parts, 1):
    name = "%s/board_test_%d.py" % (out_dir, i)
    text = (prelude + ('print("### PART %d OF %d ###")\n' % (i, len(parts)))
            + part + summary)
    io.open(name, "w", encoding="utf-8").write(text)
    print("part %d: %d bytes" % (i, len(text)))
print("PARTS=%d" % len(parts))
