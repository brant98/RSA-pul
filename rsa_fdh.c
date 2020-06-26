#include "rsa_fdh.h"
#include"miracl.h"
#include"mirdef.h"
#include<time.h>
big sign_crt_fdh(char* text, big d, big p, big q)
{
	big s, p1, q1, m, primes[2], pm[2], inv, dp, dq;//��������
	miracl* mip = mirsys(36, 0);
	big_chinese ch;
	//������ʼ��
	s = mirvar(0);
	p1 = mirvar(0);
	q1 = mirvar(0);
	m = mirvar(0);
	primes[0] = mirvar(0);
	primes[1] = mirvar(0);
	pm[0] = mirvar(0);
	pm[1] = mirvar(0);
	inv = mirvar(0);
	dp = mirvar(0);
	dq = mirvar(0);

	primes[0] = p;
	primes[1] = q;
	crt_init(&ch, 2, primes);
	xgcd(p, q, inv, inv, inv);   /* 1/p mod q */
	decr(p, 1, p1);//p1=p-1,�����p��ŷ������
	decr(q, 1, q1);//q1=q-1�������q��ŷ������

	//CRTǩ��
	copy(d, dp);//dp=d
	copy(d, dq);//dq=d
	divide(dp, p1, p1);   /* dp=d mod p-1 *///divide(x, y, z) z=x/y; x=x mod y
	divide(dq, q1, q1);   /* dq=d mod q-1 */

	//FDHǩ��,����Ϣ���й�ϣ
	char hash[20];
	char hash_text[45] = { 0 };
	int i;
	sha sh;
	shs_init(&sh);
	for (i = 0; text[i] != 0; i++)
		shs_process(&sh, text[i]);
	shs_hash(&sh, hash);

	for (i = 0; i < 20; ++i)
	{
		sprintf_s(hash_text + (i * 2), 45 - i * 2, "%02X", (unsigned char)hash[i]);

	}

	mip->IOBASE = 16;
	cinstr(m, hash_text);

	mip->IOBASE = 10;//�˴����׳���ת��ǰ���ܽ�������ģ���������
	printf("\nAlice is signing the test string\n");
	powmod(m, dp, p, pm[0]);    /* get result mod p */
	powmod(m, dq, q, pm[1]);    /* get result mod q */
	crt(&ch, pm, s);
	return s;
}
void check_crt_fdh(char* text, big s, big e, big p, big q)
{
	big  m, p1, q1, info, primes[2], pm[2], inv, dp, dq, temp;//��������
	miracl* mip = mirsys(36, 0);
	big_chinese ch;
	//������ʼ��
	m = mirvar(0);
	p1 = mirvar(0);
	q1 = mirvar(0);
	info = mirvar(0);
	primes[0] = mirvar(0);
	primes[1] = mirvar(0);
	pm[0] = mirvar(0);
	pm[1] = mirvar(0);
	inv = mirvar(0);
	dp = mirvar(0);
	dq = mirvar(0);
	temp = mirvar(0);

	primes[0] = p;
	primes[1] = q;
	crt_init(&ch, 2, primes);
	xgcd(p, q, inv, inv, inv);   /* 1/p mod q */
	decr(p, 1, p1);//p1=p-1,�����p��ŷ������
	decr(q, 1, q1);//q1=q-1�������q��ŷ������

	//CRT����ǩ����֤
	copy(e, dp);//dp=e
	copy(e, dq);//dq=e
	divide(dp, p1, p1);   /* dp=d mod p-1 *///divide(x, y, z) z=x/y; x=x mod y
	divide(dq, q1, q1);   /* dq=d mod q-1 */

	mip->IOBASE = 10;   //�˴����׳���ת��ǰ���ܽ�������ģ���������
	powmod(s, dp, p, pm[0]);    /* get result mod p */
	powmod(s, dq, q, pm[1]);    /* get result mod q */
	crt(&ch, pm, temp);
	crt_end(&ch);


	//FDHǩ����֤
	unsigned char hash[20];
	char hash_text[60] = { 0 };
	int i;
	sha sh;
	shs_init(&sh);
	for (i = 0; text[i] != 0; i++)
		shs_process(&sh, text[i]);
	shs_hash(&sh, hash);
	for (i = 0; i < 20; ++i)
	{
		sprintf_s(hash_text + (i * 2), 60 - i * 2, "%02X", hash[i]);
	}
	mip->IOBASE = 16;
	cinstr(m, hash_text);
	mip->IOBASE = 10;
	if (mr_compare(temp, m) == 0)
	{
		printf("After checking the signature,the result shows that this message is belong to Alice!\n");
	}
	else {
		printf("The result shows that this is not signed by Alice!");
	}
}
