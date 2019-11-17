
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

static const char hexcharset[] = "0123456789abcdef";
static std::string hexencode(std::string s) {
	std::string ret;
	for (char c : s) {
		ret.push_back(hexcharset[(c >> 4) & 15]);
		ret.push_back(hexcharset[c & 15]);
	}
	return ret;
}
static unsigned char hexdec(char c) {
	if (c >= '0' && c <= '9')
		return c - '0';
	else if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	else if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return 0;
}
static std::string hexdecode(std::string s) {
	if (s.size() & 1)
		return {};
	std::string ret;
	for (unsigned i = 0; i < s.size(); i += 2)
		ret.push_back((char)((hexdec(s[i]) << 4) | hexdec(s[i+1])));
	return ret;
}

static std::string b32pad(std::string s) {
	unsigned pn = (8 - (s.size() & 7)) & 7;
	while (pn--)
		s.push_back('=');
	return s;
}

static std::string b32dec(std::string s) {
	std::string ret;
	uint64_t ac = 0;
	for (unsigned i = 0; i < s.size(); i++) {
		ac <<= 5;
		char ch = toupper(s[i]);
		if (ch >= 'A' && ch <= 'Z')
			ac |= ch - 'A';
		else if (ch >= '2' && ch <= '7')
			ac |= ch - '2' + 26;
		else if (ch != '=')
			return {};

		if ((i & 7) == 7) {
			for (unsigned j = 0; j < 5; j++)
				ret.push_back((ac >> ((4-j) * 8)) & 255);
		}
	}
	// If padded correctly we just need to shave some bytes from end
	if (!s.empty()) {
		static const uint8_t ptab[8] = {0, 1, 1, 2, 3, 3, 4, 4};
		size_t l = s.find_last_not_of('=') + 1;
		size_t extra = ptab[(s.size() - l) & 7];
		ret = ret.substr(0, ret.size() - extra);
	}
	return ret;
}

static std::string trim(const std::string &s) {
	auto ps = s.find_first_not_of(' ');
	if (ps == std::string::npos)
		return {};
	auto pe = s.find_last_not_of(' ');
	return s.substr(ps, pe + 1 - ps);
}

static std::string urldec(const std::string &s) {
	std::string ret;
	for (unsigned i = 0; i < s.size(); i++) {
		if (s[i] == '%' && i + 2 < s.size()) {
			ret += hexdecode(s.substr(i+1, 2));
			i += 2;
		}
		else
			ret.push_back(s[i]);
	}
	return ret;
}

static std::unordered_map<std::string, std::string> parse_cookies(std::string jar) {
	std::unordered_map<std::string, std::string> cookies;
	size_t p = 0;
	while (1) {
		size_t pe = jar.find(';', p);
		std::string curc = pe != std::string::npos ? jar.substr(p, pe - p) : jar.substr(p);
		size_t peq = curc.find('=');
		if (peq != std::string::npos)
			cookies[trim(curc.substr(0, peq))] = trim(curc.substr(peq+1));
		if (pe == std::string::npos)
			break;
		p = pe + 1;
	}

	return cookies;
}

static std::unordered_map<std::string, std::string> parse_vars(std::string body) {
	std::unordered_map<std::string, std::string> vars;
	size_t p = 0;
	while (1) {
		size_t pe = body.find('&', p);
		std::string curv = pe != std::string::npos ? body.substr(p, pe - p) : body.substr(p);
		size_t peq = curv.find('=');
		if (peq != std::string::npos)
			vars[urldec(curv.substr(0, peq))] = urldec(curv.substr(peq+1));
		if (pe == std::string::npos)
			break;
		p = pe + 1;
	}

	return vars;
}

static std::string hmac_sha1(std::string key, std::string msg) {
	uint8_t hash[20];
	unsigned hsize = sizeof(hash);
	HMAC(EVP_sha1(), key.c_str(), key.size(), (uint8_t*)msg.c_str(), msg.size(), hash, &hsize);
	return std::string((char*)hash, sizeof(hash));
}

static std::string randstr() {
	char buf[256];
	RAND_bytes((uint8_t*)buf, sizeof(buf));
	return std::string(buf, sizeof(buf));
}

static std::string stripnl(const std::string &s) {
	std::string ret;
	for (char c : s)
		if (c != '\n' && c != '\r')
			ret.push_back(c);
	return ret;
}


