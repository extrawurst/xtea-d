module xtea.XteaCrypto;

/++ 
 +	XTEA helper type
 +	see: http://en.wikipedia.org/wiki/XTEA
+/
public struct XTEA
{
	/// XTEA delta constant
	private enum int DELTA = cast(int)0x9E3779B9;

	/// Key - 4 integer
	private int[4] m_key;

	/// Round to go - 64 are commonly used
	private int m_rounds;

	/// c'tor
	public this(int[4] _key, int _rounds)
	{
		m_key = _key;
		m_rounds = _rounds;
	}

	/// Encrypt given byte array (length to be crypted must be 8 byte aligned)
	public alias Crypt!(EncryptBlock) Encrypt;
	/// Decrypt given byte array (length to be crypted must be 8 byte aligned)
	public alias Crypt!(DecryptBlock) Decrypt;

	///
	private const void Crypt(alias T)(byte[] _bytes, size_t _offset=0, long _count=-1)
	{
		if(_count == -1)
			_count = cast(long)(_bytes.length - _offset);

		assert(_count % 8 == 0);

		for (size_t i = _offset; i < (_offset+_count); i += 8)
			T(_bytes, i);
	}

	/// Encrypt given block of 8 bytes
	private const void EncryptBlock(byte[] _bytes, size_t _offset)
	{
		auto v0 = ReadInt(_bytes, _offset);
		auto v1 = ReadInt(_bytes, _offset + 4);

		int sum = 0;

		foreach (i; 0..m_rounds)
		{
			v0 += ((v1 << 4 ^ cast(int)(cast(uint)v1 >> 5)) + v1) ^ (sum + m_key[sum & 3]);
			sum += DELTA;
			v1 += ((v0 << 4 ^ cast(int)(cast(uint)v0 >> 5)) + v0) ^ (sum + m_key[cast(int)(cast(uint)sum >> 11) & 3]);
		}

		StoreInt(v0, _bytes, _offset);
		StoreInt(v1, _bytes, _offset + 4);
	}

	/// Decrypt given block of 8 bytes
	private const void DecryptBlock(byte[] _bytes, size_t _offset)
	{
		auto v0 = ReadInt(_bytes, _offset);
		auto v1 = ReadInt(_bytes, _offset + 4);

		auto sum = cast(int)(cast(uint)DELTA * cast(uint)m_rounds);

		foreach (i; 0..m_rounds)
		{
			v1 -= ((v0 << 4 ^ cast(int)(cast(uint)v0 >> 5)) + v0) ^ (sum + m_key[cast(int)(cast(uint)sum >> 11) & 3]);
			sum -= DELTA;
			v0 -= ((v1 << 4 ^ cast(int)(cast(uint)v1 >> 5)) + v1) ^ (sum + m_key[sum & 3]);
		}

		StoreInt(v0, _bytes, _offset);
		StoreInt(v1, _bytes, _offset + 4);
	}

	/// Read 32 bit int from buffer
	private static int ReadInt(byte[] _bytes, size_t _offset) pure nothrow
	{
		return (((_bytes[_offset++] & 0xff) << 0)
				| ((_bytes[_offset++] & 0xff) << 8)
				| ((_bytes[_offset++] & 0xff) << 16)
				| ((_bytes[_offset] & 0xff) << 24));
	}

	/// Write 32 bit int from buffer
	private static void StoreInt(int _value, byte[] _bytes, size_t _offset) pure nothrow
	{
		auto unsignedValue = cast(uint)_value;
		_bytes[_offset++] = cast(byte)(unsignedValue >> 0);
		_bytes[_offset++] = cast(byte)(unsignedValue >> 8);
		_bytes[_offset++] = cast(byte)(unsignedValue >> 16);
		_bytes[_offset] = cast(byte)(unsignedValue >> 24);
	}
}

unittest
{
    import std.algorithm:equal;
    import std.stdio;

    enum byte[] sourceData = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15];
    
    auto crypto = XTEA([1,2,3,4], 64);
    
    auto data = sourceData.dup;

    writeln("\nunittest starting:\n");

    writefln("data:\t\t%s",data);
    
    crypto.Encrypt(data);
    
    writefln("encrypted:\t%s",data);
    
    crypto.Decrypt(data);
    
    writefln("decrypted:\t%s",data);
    
    assert(equal(sourceData,data));

    writeln("\nunittest ended");
}
