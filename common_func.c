#include"common_func.h"
#include"miracl.h"
#include"mirdef.h"
#include<time.h>


void creat_key(big* p, big* q, big* n, big* d, big* e)//公私钥生成函数
{
	big p1, q1, phi, t;//p和q为随机生成的素数，n为大数
	time_t seed;
	time(&seed);
	irand((unsigned int)seed);//随机数种子
	//变量初始化
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
	//生成随机素数
	do
	{
		bigbits(512, *p); //该函数使用到了irand()随机产生512位的大数p，需要注意的是产生的并非是素数。
		if (subdivisible(*p, 2)) //判断随机数p是否为偶数，如果为偶数那么加1，即为奇数，偶数一定不是素数。
			incr(*p, 1, *p);   //p=p+1
		while (!isprime(*p))   //判断p是否为素数，此时每次加2，保证p为奇数，不为偶数。
			incr(*p, 2, *p);   //此处结束的话p 便为一个素数了。
		bigbits(512, *q);   //同理前面素数p的随机生成过程，生成另一个随机素数q。此处不再一一赘述。
		if (subdivisible(*q, 2))
			incr(*q, 1, *q);
		while (!isprime(*q))
			incr(*q, 2, *q);
		multiply(*p, *q, *n);      //生成难分解的大数 n，n为两个素数的乘积， n=p*q
		lgconv(65537L, *e);  //将long型的e,转换成big型。e为公钥的一部分
		decr(*p, 1, p1);//p1=p-1,计算出p的欧拉函数
		decr(*q, 1, q1);//q1=q-1，计算出q的欧拉函数
		multiply(p1, q1, phi);  //计算n的欧拉函数，n=p*q,因为p,q都为素数，所以可以用其各自的欧拉函数来计算n的欧拉函数。
	} while (xgcd(*e, phi, *d, *d, t) != 1);//e 和d互素
}