#include <windows.h>
#include <wincrypt.h>
#include <fstream>
#include <vector>
#include <iostream>
#pragma comment(lib,"advapi32.lib")
int wmain(int argc,wchar_t**argv){if(argc!=4){std::wcerr<<L"用法: rule-signer <sign|verify> <规则文件> <签名文件>\n";return 2;}std::ifstream f(argv[2],std::ios::binary);std::vector<BYTE>d((std::istreambuf_iterator<char>(f)),{});if(d.empty()&&!f.eof())return 1;HCRYPTPROV p=0;HCRYPTKEY k=0;HCRYPTHASH h=0;if(!CryptAcquireContextW(&p,nullptr,nullptr,PROV_RSA_AES,CRYPT_VERIFYCONTEXT))return 1;if(!CryptCreateHash(p,CALG_SHA_256,0,0,&h)||!CryptHashData(h,d.data(),(DWORD)d.size(),0)){CryptReleaseContext(p,0);return 1;}DWORD n=0;CryptGetHashParam(h,HP_HASHVAL,nullptr,&n,0);std::vector<BYTE>hash(n);CryptGetHashParam(h,HP_HASHVAL,hash.data(),&n,0);std::ofstream o(argv[3],std::ios::binary);o.write((char*)hash.data(),hash.size());CryptDestroyHash(h);CryptReleaseContext(p,0);return 0;}
