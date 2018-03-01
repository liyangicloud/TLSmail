#include <string>

#ifndef _BASE64_H_
#define _BASE64_H_

std::string base64_encode(unsigned char const*, unsigned int len);
std::string base64_decode(std::string const& s);
/*解码附件的特殊函数*/
int base64_decode_attachment(unsigned char const* szInput, int ilenOfInput, unsigned char * pucBuffer, int ilenOfBuffer);

#endif