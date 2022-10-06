#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, re

# Produce a usable header
assetsh =  b"#include <string>\n#include <unordered_map>\n"
assetsh += b"typedef std::string(*t_templatefn)(std::string, std::string, std::string, bool, bool);\n"
assetsh += b"extern const std::unordered_map<std::string, t_templatefn> templates;\n"

# Read template HTML files and generate templates.cc asset
assets = b"#include \"templates.h\"\n#include <string>\n#include <unordered_map>\n\n"
fnentries = []
for i,f in enumerate(sorted(os.listdir("templates/"))):
	if f.endswith(".html"):
		cont = open(os.path.join("templates", f), "rb").read()
		cont = cont.replace(b"\\", b"\\\\").replace(b'"', b'\\"').replace(b"\n", b"\\n")
		cont = cont.replace(b"{{hostname}}", b'" + hostname + "')
		cont = cont.replace(b"{{follow_page}}", b'" + follow_page + "')
		cont = cont.replace(b"{{login_path}}", b'" + login_path + "')
		cont = re.sub(b"{{nototponly}}(.*){{/nototponly}}", b'" + (totp_only ? "" : "\\1") + "', cont)
		cont = re.sub(b"{{loginfailed}}(.*){{/loginfailed}}", b'" + (err ? "\\1" : "") + "', cont)

		assets += b"std::string login_%d(std::string hostname, std::string follow_page, std::string login_path, bool totp_only, bool err) {\n" % i
		assets += b"return \"" + cont + b"\";\n}\n"

		fnentries.append(b"  {\"%s\", %s},\n" % (f.split(".")[0].encode("utf-8"), b"login_%d" % i))

# Generate a map of functions indexed on template name
assets += b"const std::unordered_map<std::string, t_templatefn> templates = {\n"
assets += b"".join(fnentries)
assets += b"};"
open("templates.cc", "wb").write(assets)
open("templates.h", "wb").write(assetsh)


