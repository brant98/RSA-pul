#include"miracl.h"
#include"mirdef.h"
//��ͷ�ļ����ڴ�ź�RSA���ܽ������
big encrypt_normal(char* text, big n, big e);//��ͨģʽRSA����
void decrypt_normal(big c, big n, big d);//��ͨģʽRSA����

big encrypt_crt(char* text, big e, big p, big q);//CRTģʽ����
void decrypt_crt(big c, big d, big p, big q);//CRTģʽ����

big sign_normal(char* text, big n, big d);//��ͨģʽǩ��������ǩ��s
void check_sign_normal(char* text, big s, big e, big n);//��ͨģʽ��֤ǩ������չʾ����֤Ч��

big sign_crt(char* text, big d, big p, big q);//crtģʽ����ǩ��������ǩ��s
void check_sign_crt(char* text, big s, big e, big p, big q);//crtģʽ����ǩ����֤����չʾ����֤Ч��

