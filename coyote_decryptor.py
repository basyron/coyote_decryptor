from __future__ import annotations

from contextlib import suppress
from base64 import b64decode
from os import mkdir
from typing import TYPE_CHECKING, Any, Union, Optional

if TYPE_CHECKING:
    from dnfile import dnPE
    from dnfile.mdtable import MethodDefRow

import argparse

from Crypto.Cipher import AES
import dnfile
from dnfile.enums import MetadataTables

from dncil.cil.body import CilMethodBody
from dncil.cil.error import MethodBodyFormatError
from dncil.clr.token import Token, StringToken, InvalidToken
from dncil.cil.body.reader import CilMethodBodyReaderBase

# key token indexes to dotnet meta tables
DOTNET_META_TABLES_BY_INDEX = {table.value: table.name for table in MetadataTables}


class DnfileMethodBodyReader(CilMethodBodyReaderBase):
    def __init__(self, pe: dnPE, row: MethodDefRow):
        """ """
        self.pe: dnPE = pe
        self.offset: int = self.pe.get_offset_from_rva(row.Rva)

    def read(self, n: int) -> bytes:
        """ """
        data: bytes = self.pe.get_data(self.pe.get_rva_from_offset(self.offset), n)
        self.offset += n
        return data

    def tell(self) -> int:
        """ """
        return self.offset

    def seek(self, offset: int) -> int:
        """ """
        self.offset = offset
        return self.offset


def read_dotnet_user_string(pe: dnfile.dnPE, token: StringToken) -> Union[str, InvalidToken]:
    """read user string from #US stream"""
    try:
        user_string: Optional[dnfile.stream.UserString] = pe.net.user_strings.get(token.rid)
    except UnicodeDecodeError as e:
        return InvalidToken(token.value)

    if isinstance(user_string, bytes):
        return user_string.decode()

    if user_string is None or user_string.value is None:
        return InvalidToken(token.value)

    return user_string.value


def resolve_token(pe: dnPE, token: Token) -> Any:
    """ """
    if isinstance(token, StringToken):
        return read_dotnet_user_string(pe, token)

    table_name: str = DOTNET_META_TABLES_BY_INDEX.get(token.table, "")
    if not table_name:
        # table_index is not valid
        return InvalidToken(token.value)

    table: Any = getattr(pe.net.mdtables, table_name, None)
    if table is None:
        # table index is valid but table is not present
        return InvalidToken(token.value)

    try:
        return table.rows[token.rid - 1]
    except IndexError:
        # table index is valid but row index is not valid
        return InvalidToken(token.value)


def read_method_body(pe: dnPE, row: MethodDefRow) -> CilMethodBody:
    """ """
    return CilMethodBody(DnfileMethodBodyReader(pe, row))


def format_operand(pe: dnPE, operand: Any) -> str:
    """ """
    if isinstance(operand, Token):
        operand = resolve_token(pe, operand)

    if isinstance(operand, str):
        return f'{operand}'
    elif isinstance(operand, int):
        return hex(operand)
    elif isinstance(operand, list):
        return f"[{', '.join(['({:04X})'.format(x) for x in operand])}]"
    elif isinstance(operand, dnfile.mdtable.MemberRefRow):
        if isinstance(operand.Class.row, (dnfile.mdtable.TypeRefRow,)):
            return f"{str(operand.Class.row.TypeNamespace)}.{operand.Class.row.TypeName}::{operand.Name}"
    elif isinstance(operand, dnfile.mdtable.TypeRefRow):
        return f"{str(operand.TypeNamespace)}.{operand.TypeName}"
    elif isinstance(operand, (dnfile.mdtable.FieldRow, dnfile.mdtable.MethodDefRow)):
        return f"{operand.Name}"
    elif operand is None:
        return ""

    return str(operand)


def is_decryption_method(method_body: CilMethodBody) -> bool:
    """Check if method is the decryption method."""
    opcode_sequence = [
        'ldsfld', 'brfalse.s', 'ldsfld', 'callvirt', 'ldsfld',
        'brfalse.s', 'ldsfld', 'callvirt', 'ldc.i4.s', 'newarr'
    ]

    is_method = all(str(inst.opcode) == o for inst, o in zip(method_body.instructions, opcode_sequence))
    return is_method


def get_decryption_key(pe: dnPE, method_body: CilMethodBody) -> str:
    """Get decryption key from Coyote decryption method."""
    key = str()
    for instruction in method_body.instructions:
        opcode = str(instruction.opcode)
        if opcode == "ldstr":
            key += format_operand(pe, instruction.operand)
        if opcode == "ldc.i4":
            key += str(int(format_operand(pe, instruction.operand), 16))
    return key.replace(" ", '').replace("\x00", '')


def uses_decryption_method(pe: dnPE, method_body: CilMethodBody, decryption_method: str) -> bool:
    """Check if method uses decryption method."""
    for instruction in method_body.instructions:
        operand = format_operand(pe, instruction.operand)
        if str(instruction.opcode) == "call" and operand == decryption_method:
            return True
    return False


def get_encrypted_strings(pe: dnPE, method_body: CilMethodBody) -> list:
    enc_strings = []
    for instruction in method_body.instructions:
        if str(instruction.opcode) == "ldstr":
            encrypted = format_operand(pe, instruction.operand).replace(" ", "").replace("\x00", "")
            enc_strings.append(encrypted)
    return enc_strings


def decrypt(enc_string: str, key: str) -> Union[str, bytes]:
    """Coyote decryption routine."""
    from_b64 = b64decode(enc_string)
    iv = from_b64[:16]
    enc = from_b64[16:]
    cipher = AES.new(key.encode(), AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(enc)
    with suppress(Exception):
        return decrypted.decode()
    return decrypted


def decrypt_coyote(filename):
    """Decrypt Coyote strings and images."""
    pe: dnPE = dnfile.dnPE(filename)
    decryption_method = str()
    key = str()

    print("[*] Parsing .NET PE file...")
    for row in pe.net.mdtables.MethodDef:
        if not row.ImplFlags.miIL or any((row.Flags.mdAbstract, row.Flags.mdPinvokeImpl)):
            # skip methods that do not have a method body
            continue

        body: CilMethodBody = read_method_body(pe, row)

        if not body.instructions:
            continue

        is_method = is_decryption_method(body)

        if is_method:
            print(f"[!] Found Coyote decryption method! Method Name: {row.Name}")
            key = get_decryption_key(pe, body)
            decryption_method = row.Name
            break

    if not decryption_method:
        print("[!] Unable to find Coyote decryption method. Exiting...")
        return
    
    encrypted_strings_and_images = []
    encrypted_c2_list = []

    print("[*] Looking for methods with encrypted strings...")
    for row in pe.net.mdtables.MethodDef:
        if not row.ImplFlags.miIL or any((row.Flags.mdAbstract, row.Flags.mdPinvokeImpl)):
            # skip methods that do not have a method body
            continue

        body: CilMethodBody = read_method_body(pe, row)

        if not body.instructions:
            continue

        uses_decryption = uses_decryption_method(pe, body, decryption_method)

        if not uses_decryption:
            continue

        enc_list = get_encrypted_strings(pe, body)
        
        if enc_list:
            print(f"[!] Found method with encrypted strings! Method name: {row.Name}")

        if len(enc_list) > 5:
            encrypted_strings_and_images = enc_list
        else:
            encrypted_c2_list = enc_list

    print("[*] Decrypting Coyote strings and images...")
    strings_and_images = [decrypt(si, key) for si in encrypted_strings_and_images]

    print("[*] Decrypting Coyote c2 domains...")
    c2_list = [decrypt(c2, key) for c2 in encrypted_c2_list]

    images = []
    with open("coyote_strings.txt", 'w', encoding="utf-8") as f:
        print("[*] Writing strings to file 'coyote_strings.txt'...")
        for si in strings_and_images:
            if isinstance(si, bytes) or len(si) > 120:
                with suppress(Exception):
                    images.append(b64decode(si.encode()))
                continue
            new_str = ''.join(char for char in si if char.isprintable())
            f.write(f"{new_str}\n")

    print("[*] Creating folder 'coyote_images'..." )
    with suppress(Exception):
        mkdir("coyote_images")
    
    print("[*] Writing coyote decrypted images...")
    for i, img in enumerate(images):
        with open(f"coyote_images/image_{i}.png", 'wb') as f:
            f.write(img)
    
    print("[*] Writing c2 domains to file 'coyote_c2_domains.txt'...")
    with open("coyote_c2_domains.txt", 'w') as f:
        for c2 in c2_list:
            c2_domain = ''.join(char for char in c2 if char.isprintable())
            f.write(f"{c2_domain}\n")

    print("[!] DONE")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="Decrypt Coyote .NET binary")
    parser.add_argument("path", type=str, help="Full path to Coyote .NET binary")

    decrypt_coyote(parser.parse_args().path)
