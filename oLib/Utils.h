#include <sys/stat.h>
#include <random>
#include <sstream>
#include <string.h>
#include <fstream>
#include <cstdlib>

class Utils {
	private:
	protected:
	public:
		Utils() {};

		bool file_exists(const char* absolutepath) {
			struct stat buffer;
			return (stat(absolutepath, &buffer) == 0);
		};

		int genRandNumber() {
			std::random_device rd;
			std::mt19937 rng(rd());
			std::uniform_int_distribution<int> uni(0,2000000000);
			return uni(rng);
		};

		int genRandNumber(int from, int to) {
			std::random_device rd;
			std::mt19937 rng(rd());
			std::uniform_int_distribution<int> uni(from,to);
			return uni(rng);
		};

		char* stobins(char* s) {
			char* bins;
			int slen = strlen(s);
			bins = (char*)malloc(((sizeof(*s)*slen)*8)+1);
			*(bins+(slen*8)) = '\0';

			for(int i = 0; i < slen; i++)
				for(int j = 7; j >= 0; j--)
					 *(bins+(i*8)+j) = (((*(s+i)) >> j) & 1)?'1':'0';

			return bins;
		};

		std::string getLineFromFile(char* filePath, unsigned int linenumber) {
			std::ifstream infile(filePath);
			std::string line;
			std::getline(infile,line);
			for(unsigned int i = 0; i != linenumber; std::getline(infile,line) && i++) {}
			return line;
		};

		int findstr(char* p_str, char** p_arr, unsigned int p_arrlen) {
			for(unsigned int i = 0; i < p_arrlen; i++) {
				if(strcmp(*(p_arr+i), p_str) == 0) return i;
			}
			return -1;
		}
};
