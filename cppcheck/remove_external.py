import sys
import json

f = open(sys.argv[1])
data = json.load(f)
f.close()

v = []
for el in data:
	if not ("/external/" in el['file']):
		v.append(el)

f = open(sys.argv[1], 'w')
json.dump(v, f, indent=2)
f.close()
