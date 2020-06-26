#include"miracl.h"
#include"mirdef.h"
//此头文件用于存放和RSA加密解密相关
big encrypt_normal(char* text, big n, big e);//普通模式RSA加密
void decrypt_normal(big c, big n, big d);//普通模式RSA解密

big encrypt_crt(char* text, big e, big p, big q);//CRT模式加密
void decrypt_crt(big c, big d, big p, big q);//CRT模式解密

big sign_normal(char* text, big n, big d);//普通模式签名，返回签名s
void check_sign_normal(char* text, big s, big e, big n);//普通模式验证签名，并展示出验证效果

big sign_crt(char* text, big d, big p, big q);//crt模式进行签名，返回签名s
void check_sign_crt(char* text, big s, big e, big p, big q);//crt模式进行签名验证，并展示处验证效果

