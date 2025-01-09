
import sys
from pathlib import Path

rename_full = {
    "addrspacecast"      : "addrspacecast",
    "addwithoverflow"    : "addwithoverflow",
    "aligncast"          : "aligncast",
    "alignof"            : "alignof",
    "as"                 : "as",
    "atomicload"         : "atomicload",
    "atomicrmw"          : "atomicrmw",
    "atomicstore"        : "atomicstore",
    "bitcast"            : "bitcast",
    "bitoffsetof"        : "bitoffsetof",
    "bitsizeof"          : "bitsizeof",
    "branchhint"         : "branchhint",
    "breakpoint"         : "breakpoint",
    "muladd"             : "muladd",
    "byteswap"           : "byteswap",
    "bitreverse"         : "bitreverse",
    "offsetof"           : "offsetof",
    "call"               : "call",
    "cdefine"            : "cdefine",
    "cimport"            : "cimport",
    "cinclude"           : "cinclude",
    "clz"                : "clz",
    "cmpxchgstrong"      : "cmpxchgstrong",
    "cmpxchgweak"        : "cmpxchgweak",
    "compileerror"       : "compileerror",
    "compilelog"         : "compilelog",
    "constcast"          : "constcast",
    "ctz"                : "ctz",
    "cundef"             : "cundef",
    "cvaarg"             : "cvaarg",
    "cvacopy"            : "cvacopy",
    "cvaend"             : "cvaend",
    "cvastart"           : "cvastart",
    "divexact"           : "divexact",
    "divfloor"           : "divfloor",
    "divtrunc"           : "divtrunc",
    "embedfile"          : "embedfile",
    "enumfromint"        : "enumfromint",
    "errorfromint"       : "errorfromint",
    "errorname"          : "errorname",
    "errorreturntrace"   : "errorreturntrace",
    "errorcast"          : "errorcast",
    "export"             : "export",
    "extern"             : "extern",
    "field"              : "field",
    "fieldparentptr"     : "fieldparentptr",
    "FieldType"          : "FieldType",
    # "FieldType"          : "fieldtype",
    "floatcast"          : "floatcast",
    "floatfromint"       : "floatfromint",
    "frameaddress"       : "frameaddress",
    "hasdecl"            : "hasdecl",
    "hasfield"           : "hasfield",
    "import"             : "import",
    "incomptime"         : "incomptime",
    "intcast"            : "intcast",
    "intfrombool"        : "intfrombool",
    "intfromenum"        : "intfromenum",
    "intfromerror"       : "intfromerror",
    "intfromfloat"       : "intfromfloat",
    "intfromptr"         : "intfromptr",
    "max"                : "max",
    "memcpy"             : "memcpy",
    "memset"             : "memset",
    "min"                : "min",
    "wasmmemorysize"     : "wasmmemorysize",
    "wasmmemorygrow"     : "wasmmemorygrow",
    "mod"                : "mod",
    "mulwithoverflow"    : "mulwithoverflow",
    "panic"              : "panic",
    "popcount"           : "popcount",
    "prefetch"           : "prefetch",
    "ptrcast"            : "ptrcast",
    "ptrfromint"         : "ptrfromint",
    "rem"                : "rem",
    "returnaddress"      : "returnaddress",
    "select"             : "select",
    "setevalbranchquota" : "setevalbranchquota",
    "setfloatmode"       : "setfloatmode",
    "setruntimesafety"   : "setruntimesafety",
    "shlexact"           : "shlexact",
    "shlwithoverflow"    : "shlwithoverflow",
    "shrexact"           : "shrexact",
    "shuffle"            : "shuffle",
    "sizeof"             : "sizeof",
    "splat"              : "splat",
    "reduce"             : "reduce",
    "src"                : "src",
    "sqrt"               : "sqrt",
    "sin"                : "sin",
    "cos"                : "cos",
    "tan"                : "tan",
    "exp"                : "exp",
    "exp2"               : "exp2",
    "log"                : "log",
    "log2"               : "log2",
    "log10"              : "log10",
    "abs"                : "abs",
    "floor"              : "floor",
    "ceil"               : "ceil",
    "trunc"              : "trunc",
    "round"              : "round",
    "subwithoverflow"    : "subwithoverflow",
    "tagname"            : "tagname",
    "This"               : "This",
    # "This"               : "this",
    "trap"               : "trap",
    "truncate"           : "truncate",
    "typeinfo"           : "typeinfo",
    "typename"           : "typename",
    "Type"               : "Type",
    # "Type"               : "type",
    "TypeOf"             : "TypeOf",
    # "TypeOf"             : "typeof",
    "unioninit"          : "unioninit",
    "Vector"             : "Vector",
    # "Vector"             : "vector",
    "volatilecast"       : "volatilecast",
    "workgroupid"        : "workgroupid",
    "workgroupsize"      : "workgroupsize",
    "workitemid"         : "workitemid",
}

rename = {o: r for o, r in rename_full.items() if o != r}
# rename = {o: r for o, r in rename_full.items()}

for path in sys.argv[1:]:
    path = Path(path)
    print(f"renaming {path}")

    try:

        with path.open("r") as f:
            contents = f.read()

        contents_bak = contents

        for o, r in rename.items():
            contents = contents.replace(o, r)

        with path.open("w") as f:
            f.write(contents)

    except Exception:
        print(f"error: skipping {path}")

