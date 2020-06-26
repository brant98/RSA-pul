#include"rsa_func.h"
#include"miracl.h"
#include"mirdef.h"
#include<time.h>


big encrypt_normal(char* text, big n, big e)//普通模式加密
{

	big m, c;
	miracl* mip = mirsys(36, 0);
	m = mirvar(0);
	c = mirvar(0);
	mip->IOBASE = 128;
	cinstr(m, text);//m=text

	mip->IOBASE = 10;
	printf("Encrypting the test string......\n");
	powmod(m, e, n, c);     //直接模幂运算 c=m^e mod n;
	return c;
}

void decrypt_normal(big c, big n, big d)//普通模式解密
{
	big m;
	miracl* mip = mirsys(36, 0);
	m = mirvar(0);

	//开始解密
	printf("\nDecrypting......\n");
	powmod(c, d, n, m);//直接进行模幂运算 m=c^d mod n
	mip->IOBASE = 128;
	printf("\nSuccessfully the Plaintext is: ");//输出解密后的明文
	cotnum(m, stdout);
}

big encrypt_crt(char* text, big e, big p, big q)//CRT模式对消息进行加密，返回密文
{
	big c, p1, q1, m, primes[2], pm[2], inv, dp, dq;//变量定义
	miracl* mip = mirsys(36, 0);
	big_chinese ch;
	//变量初始化
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
	decr(p, 1, p1);//p1=p-1,计算出p的欧拉函数
	decr(q, 1, q1);//q1=q-1，计算出q的欧拉函数
	//CRT加密
	copy(e, dp);//dp=e
	copy(e, dq);//dq=e
	divide(dp, p1, p1);   /* dp=d mod p-1 *///divide(x, y, z) z=x/y; x=x mod y
	divide(dq, q1, q1);   /* dq=d mod q-1 */

	mip->IOBASE = 128;
	cinstr(m, text);

	mip->IOBASE = 10;//此处容易出错，转换前不能进行运算的，否则会出错。
	printf("\nEncrypting test string\n");
	powmod(m, dp, p, pm[0]);    /* get result mod p */
	powmod(m, dq, q, pm[1]);    /* get result mod q */
	crt(&ch, pm, c);
	return c;
}

void decrypt_crt(big c, big d, big p, big q)//CRT模式进行RSA解密
{
	big  p1, q1, m, primes[2], pm[2], inv, dp, dq;//变量定义
	miracl* mip = mirsys(36, 0);
	big_chinese ch;
	//变量初始化
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
	decr(p, 1, p1);//p1=p-1,计算出p的欧拉函数
	decr(q, 1, q1);//q1=q-1，计算出q的欧拉函数
	//CRT解密
	copy(d, dp);//dp=d
	copy(d, dq);//dq=d
	divide(dp, p1, p1);   /* dp=d mod p-1 *///divide(x, y, z) z=x/y; x=x mod y
	divide(dq, q1, q1);   /* dq=d mod q-1 */

	mip->IOBASE = 10;//此处容易出错，转换前不能进行运算的，否则会出错。
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
	big m, s;//m表示待签名消息的数值模式 方便运算，s表示消息的签名
	miracl* mip = mirsys(36, 0);
	m = mirvar(0);
	s = mirvar(0);
	mip->IOBASE = 128;
	cinstr(m, text);//m=text
	mip->IOBASE = 10;
	printf("Ailce  is signing the message......\n");
	powmod(m, d, n, s);     //直接模幂运算 c=m^e mod n;
	return s;
}
void check_sign_normal(char* text, big s, big e, big n)
{
	big info, temp;
	miracl* mip = mirsys(36, 0);
	info = mirvar(0);
	temp = mirvar(0);
	mip->IOBASE = 128;
	cinstr(info, text);  //info=text对应的大数
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
	big s, p1, q1, m, primes[2], pm[2], inv, dp, dq;//变量定义
	miracl* mip = mirsys(36, 0);
	big_chinese ch;
	//变量初始化
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
	decr(p, 1, p1);//p1=p-1,计算出p的欧拉函数
	decr(q, 1, q1);//q1=q-1，计算出q的欧拉函数
	//CRT签名
	copy(d, dp);//dp=d
	copy(d, dq);//dq=d
	divide(dp, p1, p1);   /* dp=d mod p-1 *///divide(x, y, z) z=x/y; x=x mod y
	divide(dq, q1, q1);   /* dq=d mod q-1 */

	mip->IOBASE = 128;
	cinstr(m, text);

	mip->IOBASE = 10;//此处容易出错，转换前不能进行运算的，否则会出错。
	printf("\nAlice is signing the message!\n");
	powmod(m, dp, p, pm[0]);    /* get result mod p */
	powmod(m, dq, q, pm[1]);    /* get result mod q */
	crt(&ch, pm, s);
	return s;

}
void check_sign_crt(char* text, big s, big e, big p, big q)
{
	big  p1, q1, info, primes[2], pm[2], inv, dp, dq, temp;//变量定义
	miracl* mip = mirsys(36, 0);
	big_chinese ch;
	//变量初始化
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
	decr(p, 1, p1);//p1=p-1,计算出p的欧拉函数
	decr(q, 1, q1);//q1=q-1，计算出q的欧拉函数

	//CRT进行签名验证
	copy(e, dp);//dp=e
	copy(e, dq);//dq=e
	divide(dp, p1, p1);   /* dp=d mod p-1 *///divide(x, y, z) z=x/y; x=x mod y
	divide(dq, q1, q1);   /* dq=d mod q-1 */

	mip->IOBASE = 10;   //此处容易出错，转换前不能进行运算的，否则会出错。
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


