#include"rsa_func.h"
#include"miracl.h"
#include"mirdef.h"
#include<time.h>


big encrypt_normal(char* text, big n, big e)//��ͨģʽ����
{

	big m, c;
	miracl* mip = mirsys(36, 0);
	m = mirvar(0);
	c = mirvar(0);
	mip->IOBASE = 128;
	cinstr(m, text);//m=text

	mip->IOBASE = 10;
	printf("Encrypting the test string......\n");
	powmod(m, e, n, c);     //ֱ��ģ������ c=m^e mod n;
	return c;
}

void decrypt_normal(big c, big n, big d)//��ͨģʽ����
{
	big m;
	miracl* mip = mirsys(36, 0);
	m = mirvar(0);

	//��ʼ����
	printf("\nDecrypting......\n");
	powmod(c, d, n, m);//ֱ�ӽ���ģ������ m=c^d mod n
	mip->IOBASE = 128;
	printf("\nSuccessfully the Plaintext is: ");//������ܺ������
	cotnum(m, stdout);
}

big encrypt_crt(char* text, big e, big p, big q)//CRTģʽ����Ϣ���м��ܣ���������
{
	big c, p1, q1, m, primes[2], pm[2], inv, dp, dq;//��������
	miracl* mip = mirsys(36, 0);
	big_chinese ch;
	//������ʼ��
	c = mirvar(0);
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
	//CRT����
	copy(e, dp);//dp=e
	copy(e, dq);//dq=e
	divide(dp, p1, p1);   /* dp=d mod p-1 *///divide(x, y, z) z=x/y; x=x mod y
	divide(dq, q1, q1);   /* dq=d mod q-1 */

	mip->IOBASE = 128;
	cinstr(m, text);

	mip->IOBASE = 10;//�˴����׳���ת��ǰ���ܽ�������ģ���������
	printf("\nEncrypting test string\n");
	powmod(m, dp, p, pm[0]);    /* get result mod p */
	powmod(m, dq, q, pm[1]);    /* get result mod q */
	crt(&ch, pm, c);
	return c;
}

void decrypt_crt(big c, big d, big p, big q)//CRTģʽ����RSA����
{
	big  p1, q1, m, primes[2], pm[2], inv, dp, dq;//��������
	miracl* mip = mirsys(36, 0);
	big_chinese ch;
	//������ʼ��
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
	//CRT����
	copy(d, dp);//dp=d
	copy(d, dq);//dq=d
	divide(dp, p1, p1);   /* dp=d mod p-1 *///divide(x, y, z) z=x/y; x=x mod y
	divide(dq, q1, q1);   /* dq=d mod q-1 */

	mip->IOBASE = 10;//�˴����׳���ת��ǰ���ܽ�������ģ���������
	printf("\nDecrypting test string\n");
	powmod(c, dp, p, pm[0]);    /* get result mod p */
	powmod(c, dq, q, pm[1]);    /* get result mod q */
	crt(&ch, pm, m);
	mip->IOBASE = 128;
	printf("Successfully the Plaintext is: ");
	cotnum(m, stdout);
	crt_end(&ch);
}

big sign_normal(char* text, big n, big d)
{
	big m, s;//m��ʾ��ǩ����Ϣ����ֵģʽ �������㣬s��ʾ��Ϣ��ǩ��
	miracl* mip = mirsys(36, 0);
	m = mirvar(0);
	s = mirvar(0);
	mip->IOBASE = 128;
	cinstr(m, text);//m=text
	mip->IOBASE = 10;
	printf("Ailce  is signing the message......\n");
	powmod(m, d, n, s);     //ֱ��ģ������ c=m^e mod n;
	return s;
}
void check_sign_normal(char* text, big s, big e, big n)
{
	big info, temp;
	miracl* mip = mirsys(36, 0);
	info = mirvar(0);
	temp = mirvar(0);
	mip->IOBASE = 128;
	cinstr(info, text);  //info=text��Ӧ�Ĵ���
	mip->IOBASE = 10;
	powmod(s, e, n, temp);
	if (mr_compare(temp, info) == 0)
	{
		printf("After checking the signature,the result shows that this message is signed by Alice!\n");
	}
	else {
		printf("The result shows that this is not signed by Alice!");
	}

}

big sign_crt(char* text, big d, big p, big q)
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

	mip->IOBASE = 128;
	cinstr(m, text);

	mip->IOBASE = 10;//�˴����׳���ת��ǰ���ܽ�������ģ���������
	printf("\nAlice is signing the message!\n");
	powmod(m, dp, p, pm[0]);    /* get result mod p */
	powmod(m, dq, q, pm[1]);    /* get result mod q */
	crt(&ch, pm, s);
	return s;

}
void check_sign_crt(char* text, big s, big e, big p, big q)
{
	big  p1, q1, info, primes[2], pm[2], inv, dp, dq, temp;//��������
	miracl* mip = mirsys(36, 0);
	big_chinese ch;
	//������ʼ��
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
	mip->IOBASE = 128;
	cinstr(info, text);

	if (mr_compare(temp, info) == 0)
	{
		printf("After checking the signature,the result shows that this message is signed by Alice!\n");
	}
	else {
		printf("The result shows that this is not signed by Alice!");
	}
}


