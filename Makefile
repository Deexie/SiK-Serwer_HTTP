FLAGS=-Wall -Wextra -O2 -std=c++17
FILE=main.cpp

all: serwer

serwer: main.cpp
	g++ $(FLAGS) $(FILE) -o serwer

clean:
	rm -f serwer
