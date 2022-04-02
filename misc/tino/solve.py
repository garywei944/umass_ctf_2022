with open('test.tino.cpp', 'r') as f:
    lines = f.read().split('\n')

code_map = {}

for line in lines:
    if line.startswith('#define'):
        try:
            _, k, v = line.split(' ', 2)
            code_map[k] = v
        except ValueError:
            print(line)

# print(code_map)

tokens = []

for token in lines[-1].split():
    tokens.append(code_map[token])

source_code = ' '.join(tokens)

with open('tino.cpp', 'w') as f:
    f.write('\n'.join(lines[:5]))
    f.write('\n')
    f.write(source_code)
