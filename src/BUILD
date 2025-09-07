cc_binary(
    name = "memory_analyzer",
    srcs = [
        "disassembler.cc",
        "disassembler.h",
        "dllmain.cc",
        "dllmain.h",
        "logger.cc",
        "logger.h",
        "memory_analyzer.cc",
        "memory_analyzer.h",
        "object.cc",
        "object.h",
    ],
    deps = [
        "//mnemosyne",
        "//third_party/detours",
        "//third_party/zydis",
    ],
    linkshared = True,
    copts = ["/W4", "/O2", "/std:c++17"],
)
