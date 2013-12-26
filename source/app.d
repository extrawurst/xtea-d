import std.stdio;

import std.algorithm;
import xtea.XteaCrypto;

void main()
{ 
	enum byte[] sourceData = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15];

	auto crypto = new XTEA([1,2,3,4], 64);

	auto data = sourceData.dup;

	writefln("data:\t\t%s",data);

	crypto.Encrypt(data);

	writefln("encrypted:\t%s",data);

	crypto.Decrypt(data);

	writefln("decrypted:\t%s",data);

	assert(equal(sourceData,data));
}
