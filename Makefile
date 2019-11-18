
all:
	# Produce templates.cc/h
	./templ.py
	g++ -Wall -O2 -ggdb -o server.bin server.cc templates.cc -lfcgi++ -lfcgi -lpthread -lconfig -lcrypto

