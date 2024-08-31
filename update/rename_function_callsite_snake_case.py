
import csv
import regex
from pathlib import Path
from typing import TextIO
from pprint import pprint
from functools import cache

import click
import pandas as pd

pattern_chcase = regex.compile(r"(?<=[a-z])(?=[A-Z])|[^a-zA-Z]")
pattern_chcase = regex.compile(r"(?<=[a-z0-9])(?=[A-Z])|[^a-zA-Z0-9]")

# pattern_fndecl = regex.compile(r"fn ([a-z_][a-zA-Z0-9_])*")
# pattern_fndecl = regex.compile(r"fn ([a-zA-Z0-9_]+)")


# @cache
def to_snake_case(s: str, df: pd.DataFrame):
    if s not in df['old'].values:
        return s
    s_new = df.loc[df['old'] == s]["new"].iloc[0]
    # print(f"{s:<50} -> {s_new}")
    # return s
    return s_new

def to_snake_case_match(m: regex.Match, df: pd.DataFrame):
    # print(m)
    s = m.group(1)
    return to_snake_case(s, df)

def convert_file_snake_case(f: TextIO, df: pd.DataFrame, pattern: regex.Match):
    content = f.read()
    content_new = pattern.sub(lambda m: to_snake_case_match(m, df), content)
    # for i, row in df.iterrows():
    #     print(i, row["old"], row["new"])
    #     content_new = regex.sub(row["old"], row["new"], content)
    return content_new

@click.command()
@click.argument("files", nargs=-1, type=Path)
@click.option("-m", "--map", type=Path)
def rename_function_callsite_snake_case(
    files: list[Path],
    map: Path,
):
    df = pd.read_csv(map, dtype={"old": str, "new": str}, keep_default_na=False)
    # print(df)

    # print(type(df["old"]))
    # if "addWasiUpdateStep" in df['old'].values:
    #     print("here")

    print("compiling pattern")
    p = rf'\b({r"|".join(df["old"].values)})\b'
    pattern = regex.compile(p)
    # print(pattern.pattern)
    print("compiling pattern (done)")
    # exit(0)

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
            converted = convert_file_snake_case(f, df, pattern)
        with file.open("w") as f:
            f.write(converted)



if __name__ == "__main__":
    rename_function_callsite_snake_case()

