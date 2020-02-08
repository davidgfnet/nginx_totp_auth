
all:
	# Produce templates.cc/h
	./templ.py
	g++ -Wall -std=c++17 -O2 -ggdb -o server.bin server.cc templates.cc -lfcgi++ -lfcgi -lpthread -lconfig -lcrypto

