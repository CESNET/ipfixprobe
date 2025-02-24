#pragma once

#include <string>

namespace ipxp {

class Argument {
public:
	Argument &help(std::string help) {
		m_help = std::move(help);
		return *this;
	}

	Argument &metavar(std::string metavar) {
		m_metavar = std::move(metavar);
		return *this;
	}

	Argument &required() {
		m_is_required = true;
		return *this;
	}

	/*
	Argument &flag() {
		default_value(false);
		implicit_value(true);
		return *this;
	}
		*/



private:
	std::string m_help;
	std::string m_metavar;
	bool m_is_required = false;
};

class OptionParser {

};

} // namespace ipxp