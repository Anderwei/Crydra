import string


class Value:
    def __init__(self, value, address, index, encoding, xor=b''):
        self.value = value
        self.address = address
        self.index = int(index)
        self.encoding = [
            '"big"',    # big endian
            '"little"',  # little endian
            '"bnb"',    # big endian -> negative -> big endian
            '"bnl"',    # big endian -> negative -> little endian
            '"lnb"',    # little endian -> negative -> big endian
            '"lnl"',    # little endian -> negative -> little endian
        ][int(encoding)]
        self.xor = xor

    @staticmethod
    def _printable_bytes(data):
        printable_chars = set(string.printable.encode('ascii'))
        return all(char in printable_chars for char in data)

    def __str__(self):
        output = f'({self.index},0x{self.value.hex()},{self.encoding}'
        if self.xor:
            if self._printable_bytes(self.xor):
                output += f' (⊕ {self.xor.decode()})'
            else:
                output += f' (⊕ 0x{self.xor.hex()})'
        output += f',0x{self.address:x})'
        return output


class Group:
    def __init__(self, blocksize, values):
        self.blocksize = blocksize
        self.values = values

    def __str__(self):
        output = '{' + {0: '"fullword"', 8: '"qword"', 4: '"dword"'}[self.blocksize] + ":["
        # for value in self.values:
        #     output += f'    | {value}\n'
        output += ",".join(map(str,self.values)) + "]}"
        return output.strip('\n')


class Result:
    def __init__(self, name):
        self.name = name
        self.groups = []

    def __str__(self):
        output = ''
        output += "{" + f'"{self.name}" : '

        groups_string = []
        for group in self.groups:
            groups_string.append(str(group))
        output += "[" + ",".join(groups_string) + "]}"
        print(output)
        return output.strip('\n')


class Match:
    def __init__(self, match=None):
        self.values = {0: [], 8: [], 4: []}
        self.add(match)

    def add(self, match):
        if match:
            self.name = match.meta['name']
            self.length = match.meta['length']
            for address, varname, value in match.strings:
                _, size, index, encoding = varname.split('_')
                self.values[int(size)].append(Value(value, address, index, encoding))
