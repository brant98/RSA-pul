#include"common_func.h"
#include"miracl.h"
#include"mirdef.h"
#include<time.h>


void creat_key(big* p, big* q, big* n, big* d, big* e)//��˽Կ���ɺ���
{
	big p1, q1, phi, t;//p��qΪ������ɵ�������nΪ����
	time_t seed;
	time(&seed);
	irand((unsigned int)seed);//���������
	//������ʼ��
	*p = mirvar(0);
	*q = mirvar(0);
	*n = mirvar(0);
	*d = mirvar(0);
	*e = mirvar(0);
	p1 = mirvar(0);
	q1 = mirvar(0);
	phi = mirvar(0);
	t = mirvar(0);
	//printf("Now generating 512-bit random primes p and q\n\n");
	//�����������
	do
	{
		bigbits(512, *p); //�ú���ʹ�õ���irand()�������512λ�Ĵ���p����Ҫע����ǲ����Ĳ�����������
		if (subdivisible(*p, 2)) //�ж������p�Ƿ�Ϊż�������Ϊż����ô��1����Ϊ������ż��һ������������
			incr(*p, 1, *p);   //p=p+1
		while (!isprime(*p))   //�ж�p�Ƿ�Ϊ��������ʱÿ�μ�2����֤pΪ��������Ϊż����
			incr(*p, 2, *p);   //�˴������Ļ�p ��Ϊһ�������ˡ�
		bigbits(512, *q);   //ͬ��ǰ������p��������ɹ��̣�������һ���������q���˴�����һһ׸����
		if (subdivisible(*q, 2))
			incr(*q, 1, *q);
		while (!isprime(*q))
			incr(*q, 2, *q);
		multiply(*p, *q, *n);      //�����ѷֽ�Ĵ��� n��nΪ���������ĳ˻��� n=p*q
		lgconv(65537L, *e);  //��long�͵�e,ת����big�͡�eΪ��Կ��һ����
		decr(*p, 1, p1);//p1=p-1,�����p��ŷ������
		decr(*q, 1, q1);//q1=q-1�������q��ŷ������
		multiply(p1, q1, phi);  //����n��ŷ��������n=p*q,��Ϊp,q��Ϊ���������Կ���������Ե�ŷ������������n��ŷ��������
	} while (xgcd(*e, phi, *d, *d, t) != 1);//e ��d����
}