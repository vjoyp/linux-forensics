import os

def load_symbols(symbol_file):
    """
    Load symbols from the nm output file.
    Returns a dictionary mapping addresses to symbols.
    """
    symbols = {}
    with open(symbol_file, "r") as f:
        for line in f:
            parts = line.split()
            if len(parts) >= 3:
                addr, symbol_type, name = parts[0], parts[1], parts[2]
                symbols[int(addr, 16)] = name
    return symbols


def lookup_symbol(address, symbols):
    """
    Find the nearest symbol for a given address.
    """
    addresses = sorted(symbols.keys())
    for addr in reversed(addresses):
        if address >= addr:
            offset = address - addr
            return symbols[addr], offset
    return None, None


def extract_mixed_mode_code(ramdump_file, address, size=32):
    """
    Extract mixed-mode code (assembly and potential disassembly) near an address.
    """
    code = []
    with open(ramdump_file, "rb") as f:
        f.seek(address)
        data = f.read(size)
        for i in range(0, len(data), 4):  # Assuming 4-byte instructions
            word = int.from_bytes(data[i:i + 4], byteorder="little")
            code.append(f"0x{address + i:08X}: 0x{word:08X}")
    return code


def main():
    # Inputs
    pc = int(input("Enter the Program Counter (PC) address (hex): "), 16)
    lr = int(input("Enter the Link Register (LR) address (hex): "), 16)
    symbol_file = input("Enter the path to the symbol dump file (nm output): ")
    ramdump_file = input("Enter the path to the RAM dump file: ")

    # Load symbols
    if not os.path.exists(symbol_file):
        print(f"Symbol file '{symbol_file}' not found.")
        return
    symbols = load_symbols(symbol_file)

    # Look up symbols for PC and LR
    pc_func, pc_offset = lookup_symbol(pc, symbols)
    lr_func, lr_offset = lookup_symbol(lr, symbols)

    # Output symbol information
    print("\nCrash Analysis:")
    if pc_func:
        print(f"PC: {pc_func} + 0x{pc_offset:X} (0x{pc:X})")
    else:
        print(f"PC: No symbol found for address 0x{pc:X}")

    if lr_func:
        print(f"LR: {lr_func} + 0x{lr_offset:X} (0x{lr:X})")
    else:
        print(f"LR: No symbol found for address 0x{lr:X}")

    # Extract mixed-mode code for PC and LR
    if os.path.exists(ramdump_file):
        print("\nMixed Mode Code Near PC:")
        for line in extract_mixed_mode_code(ramdump_file, pc):
            print(line)

        print("\nMixed Mode Code Near LR:")
        for line in extract_mixed_mode_code(ramdump_file, lr):
            print(line)
    else:
        print(f"RAM dump file '{ramdump_file}' not found.")


if __name__ == "__main__":
    main()
