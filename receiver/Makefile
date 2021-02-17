include ~/Downloads/PcapPlusPlus-19.12/mk/PcapPlusPlus.mk

all:
	g++ $(PCAPPP_INCLUDES) -c -o main.o main.cpp
	g++ $(PCAPPP_LIBS_DIR) -static-libstdc++ -o generator.run main.o $(PCAPPP_LIBS)

clean:
	rm main.o
	rm generator.run
