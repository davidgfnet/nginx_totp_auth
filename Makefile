
all:
	# Produce templates.cc/h
	./templ.py
	g++ -ggdb -o server.bin server.cc templates.cc -lfcgi++ -lfcgi -lpthread -lconfig -lcrypto

