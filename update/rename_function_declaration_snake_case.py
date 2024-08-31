
import regex
from pathlib import Path
from typing import TextIO
from pprint import pprint

import click

pattern_chcase = regex.compile(r"(?<=[a-z])(?=[A-Z])|[^a-zA-Z]")
pattern_chcase = regex.compile(r"(?<=[a-z0-9])(?=[A-Z])|[^a-zA-Z0-9]")

# pattern_fndecl = regex.compile(r"fn ([a-z_][a-zA-Z0-9_])*")
pattern_fndecl = regex.compile(r"fn ([a-z][a-zA-Z0-9_]*)")


# pattern = regex.compile(
#     r"""
#         (?<=[a-z])      # preceded by lowercase
#         (?=[A-Z])       # followed by uppercase
#         |               #   OR
#         (?<[A-Z])       # preceded by lowercase
#         (?=[A-Z][a-z])  # followed by uppercase, then lowercase
#     """,
#     regex.X,
# )

def to_snake_case(s: str):
    s_new = pattern_chcase.sub('_', s).lower()
    print(f"{s:<50} -> {s_new}")
    return s_new

def to_snake_case_match(m: regex.Match):
    s = m.group(1)
    return f"fn {to_snake_case(s)}"

def convert_file_snake_case(f: TextIO):
    content = f.read()
    content_new = pattern_fndecl.sub(to_snake_case_match, content)
    # content_new = pattern_fndecl.sub(lambda m: to_snake_case(m.group(0)), content)
    # content_new = pattern_fndecl.sub(lambda m: f"fn {to_snake_case(m.group(0))}", content)
    return content_new

@click.command()
@click.argument("files", nargs=-1, type=Path)
# @click.option("ignore", nargs=-1, type=Path)
def rename_function_declaration_snake_case(
    files: list[Path],
    # ignore: list[Path],
):
    print(files)
    files_to_convert: list[Path] = []
    for file in files:
        if file.is_file():
            files_to_convert.append(file)
        if file.is_dir():
            files_to_convert.extend(file.glob("./**/*.zig"))

    files_to_convert = [file for file in files_to_convert if Path(".zig-cache") not in file.parents]

    pprint(files_to_convert)

    for file in files_to_convert:
        print(file)
        with file.open("r") as f:
            converted = convert_file_snake_case(f)
        with file.open("w") as f:
            f.write(converted)



if __name__ == "__main__":
    rename_function_declaration_snake_case()

