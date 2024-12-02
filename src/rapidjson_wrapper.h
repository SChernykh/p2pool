#if defined(_MSC_VER) && defined(__cppcheck__)
// cppcheck chokes on rapidjson headers in Windows
#else
#include <rapidjson/document.h>
#endif
