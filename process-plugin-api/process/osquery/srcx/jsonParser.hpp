#pragma once

#include <optional>
#include <string>

namespace ipxp
{

class JsonParser {
public:
    struct AboutProgram {
        std::string name;
        std::string username;
    };

    struct AboutOSVersion {
        std::string arch;
        std::string build;
        std::string hostname;
        std::string majorNumber;
	    std::string minorNumber;
        std::string name;
        std::string platform;
        std::string platformLike;
        std::string version;
    };

    /**
	 * Parses json by template.
	 * @return true if success or false.
	 */
	static std::optional<AboutOSVersion> parseJsonOSVersion(std::string_view jsonData) noexcept;


	/**
	 * Parses json by template.
	 * @return true if success or false.
	 */
	static std::optional<AboutProgram> parseJsonAboutProgram(std::string_view jsonData) noexcept;

    static std::optional<std::string_view> findValueByKey(std::string_view jsonData, std::string_view key);


private:

    /**
	 * Parses json string with only one element.
	 * @param[in]  singleKey    key.
	 * @param[out] singleValue  value.
	 * @return true if success or false.
	 */
	//bool parseJsonSingleItem(const std::string& singleKey, std::string& singleValue);

	/**
	 * From position \p from tries to find two strings between quotes ["key":"value"].
	 * @param[in]  from  start position in the buffer.
	 * @param[out] key   value for the "key" parsing result.
	 * @param[out] value value for the "value" parsing result.
	 * @return the position where the text search ended, 0 if end of json row or -1 if end of
	 * buffer.
	 */
	//int parseJsonItem(int from, std::string& key, std::string& value);

	/**
	 * From position \p from tries to find string between quotes.
	 * @param[in]  from start position in the buffer.
	 * @param[out] str  value for the parsing result.
	 * @return the position where the text search ended, 0 if end of json row or -1 if end of
	 * buffer.
	 */
	//int parseString(int from, std::string& str);

    /**
	 * Tries to find the position in the buffer where the json data starts.
	 * @return position number or -1 if position was not found.
	 */
	//int getPositionForParseJson();
};

} // namespace ipxp
