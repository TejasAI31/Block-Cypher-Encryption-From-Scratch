#include "SHA.h"

SHA::SHA(string mode)
{
	if (!mode.compare("256"))
	{
		version = v256;
		wordlength = 32;
		blocksize = 512;
		padding = 64;
		rounds = 64;
	}
	else if (!mode.compare("512"))
	{
		version = v512;
		wordlength = 64;
		blocksize = 1024;
		padding = 128;
		rounds = 80;
	}
	else if (!mode.compare("224"))
	{
		version = v224;
		wordlength = 32;
		blocksize = 512;
		padding = 64;
		rounds = 64;
	}
	else if (!mode.compare("384"))
	{
		version = v384;
		wordlength = 64;
		blocksize = 1024;
		padding = 128;
		rounds = 80;
	}


	InitializePrimes();
	InitializeHashes();
	InitializeKeys();
}

void SHA::InputToBits(string* input, string* destination)
{
	string finalstr = "";

	for (int i = 0; i < input->length(); i++)
	{
		finalstr = finalstr + bitset<8>((*input)[i]).to_string();
	}

	int length = finalstr.length();

	if (length % blocksize != 0)
	{
		int nextmultiple = ceil(length / blocksize) * blocksize;
		if (nextmultiple - length < padding + 1)nextmultiple += blocksize;

		//PAD 1
		finalstr += '1';

		//PAD 0's
		for (int i = length + 1; i < nextmultiple - padding; i++)
		{
			finalstr += '0';
		}

		switch (version)
		{
		case v256:
		case v224:
			finalstr += bitset<64>(length).to_string();
			break;
		case v512:
		case v384:
			finalstr += bitset<128>(length).to_string();
			break;
		}
	}

	*destination = finalstr;
	return;
}

void SHA::BitsToBlocks(string* bits)
{
	for (int i = 0; i < bits->length(); i += blocksize)
	{
		blocks.push_back(bits->substr(i, blocksize));
	}

	for (int i = 0; i < blocks.size(); i++)
	{
		if (blocks[i].length() != blocksize)
		{
			printf("ERROR IN BLOCK FORMATION");
			exit(0);
		}
	}
}

void SHA::BlocksToMessages()
{
	for (int i = 0; i < blocks.size(); i++)
	{
		vector<string> messages;

		//First 16 Messages
		for (int j = 0; j < blocks[i].length(); j += wordlength)
		{
			messages.push_back(blocks[i].substr(j, wordlength));
		}

		//Next Messages
		for (int j = 16; j < rounds; j++)
		{
			messages.push_back(BinaryAdd({ messages[j - 16],messages[j - 7],SigmaZero(messages[j - 15]),SigmaOne(messages[j - 2]) }));
		}

		messageblocks.push_back(messages);
	}
}

string SHA::BinaryAddTwoStrings(string a, string b)
{
	string finalstr = "";
	short int carry = 0;
	short int sum = 0;
	for (short int i = a.length() - 1; i >= 0; i--)
	{
		sum = a[i] + b[i] + carry - 96;
		if (carry)carry = 0;
		if (sum >= 2)
			carry = 1;
		finalstr = (char)(sum % 2 + 48) + finalstr;
	}
	return finalstr;
}

string SHA::BinaryAdd(vector<string> inputs)
{
	if (inputs.size() < 2)
	{
		return "NOT ENOUGH ENTRIES";
	}

	string sum = BinaryAddTwoStrings(inputs[0], inputs[1]);
	for (short int i = 2; i < inputs.size(); i++)
	{
		sum = BinaryAddTwoStrings(sum, inputs[i]);
	}
	return sum;
}

string SHA::Mod2Sum(vector<string> inputs)
{
	string finalstr = "";

	for (int i = 0; i < inputs[0].size(); i++)
	{
		int sum = 0;
		for (int j = 0; j < inputs.size(); j++)
		{
			sum += (int)(inputs[j][i]) - 48;
		}
		sum = sum % 2;

		finalstr += (char)(sum + 48);
	}

	return finalstr;
}

string SHA::ROTR(string input, int num)
{
	return input.substr(input.length() - num, num) + input.substr(0, input.length() - num);
}

string SHA::SHR(string input, int num)
{
	string finalstr = "";
	for (int i = 0; i < num; i++)finalstr += '0';
	finalstr += input.substr(0, input.length() - num);

	return finalstr;
}

string SHA::SigmaZero(string input)
{
	switch (version)
	{
	case v256:
	case v224:
		return Mod2Sum({ ROTR(input,7),ROTR(input,18),SHR(input,3) });
	case v512:
	case v384:
		return Mod2Sum({ ROTR(input,1),ROTR(input,8),SHR(input,7) });
	}

	return "";
}

string SHA::SigmaOne(string input)
{
	switch (version)
	{
	case v256:
	case v224:
		return Mod2Sum({ ROTR(input,17),ROTR(input,19),SHR(input,10) });
	case v512:
	case v384:
		return Mod2Sum({ ROTR(input,19),ROTR(input,61),SHR(input,6) });
	}

	return "";
}

string SHA::SummationZero(string input)
{
	switch (version)
	{
	case v256:
	case v224:
		return Mod2Sum({ ROTR(input,2),ROTR(input,13),ROTR(input,22) });
	case v512:
	case v384:
		return Mod2Sum({ ROTR(input,28),ROTR(input,34),ROTR(input,39) });
	}

	return "";
}

string SHA::SummationOne(string input)
{
	switch (version)
	{
	case v256:
	case v224:
		return Mod2Sum({ ROTR(input,6),ROTR(input,11),ROTR(input,25) });
	case v512:
	case v384:
		return Mod2Sum({ ROTR(input,14),ROTR(input,18),ROTR(input,41) });
	}
	return "";
}

string SHA::Choose(string a, string b, string c)
{
	string finalstr = "";
	for (int i = 0; i < a.length(); i++)
	{
		if (a[i] == '0')
			finalstr += c[i];
		else
			finalstr += b[i];
	}
	return finalstr;

}

string SHA::Majority(vector<string> inputs)
{
	string finalstr = "";

	for (int i = 0; i < inputs[0].length(); i++)
	{
		int zerocounter = 0;
		int onecounter = 0;

		for (int j = 0; j < inputs.size(); j++)
		{
			if (inputs[j][i] == '1')
				onecounter++;
			else
				zerocounter++;
		}

		if (zerocounter > onecounter)
			finalstr += '0';
		else
			finalstr += '1';
	}

	return finalstr;
}

string SHA::BinaryToHex(string input)
{
	string finalstr = "";

	if (input.length() % 4 != 0)
	{
		int nextmultiple = ceil(input.length() / (float)4) * 4;
		for (int i = input.length(); i < nextmultiple; i++)
		{
			input = '0' + input;
		}

		return input;
	}

	for (int i = 0; i < input.length(); i += 4)
	{
		string hexnum = input.substr(i, 4);
		int sum = 0;
		int power = 0;

		for (int j = 3; j >= 0; j--)
		{
			if (hexnum[j] == '1')
				sum += (int)pow(2, power);
			power++;
		}

		if (sum < 10)
		{
			finalstr += (char)(sum + 48);
		}
		else
		{
			finalstr += (char)(sum + 87);
		}
	}

	return finalstr;
}

void SHA::InitializePrimes()
{
	int counter = 0;
	int prime = 2;
	while (counter < 100)
	{
		bool primeflag = true;
		for (int i = 2; i <= prime / 2; i++)
		{
			if (prime % i == 0)
			{
				primeflag = false;
				break;
			}
		}

		if (primeflag)
		{
			primes.push_back(prime);
			counter++;
		}

		prime++;
	}
}

void SHA::InitializeHashes()
{
	for (int i = 0; i < 8; i++)
	{
		long double sqroot;
		long double fraction;
		unsigned long long int mult = 0;

		switch (version)
		{
		case v224:
			mult = h224[i];
			break;
		case v256:
			sqroot = sqrt(primes[i]);
			fraction = sqroot - (int)sqroot;
			mult = fraction * pow(2, wordlength);
			break;
		case v512:
			mult = h512[i];
			break;
		case v384:
			mult = h384[i];
			break;
		}


		string hash;

		switch (version)
		{
		case v256:
		case v224:
			hash = bitset<32>(mult).to_string();
			break;
		case v512:
		case v384:
			hash = bitset<64>(mult).to_string();
			break;
		}
		temphashes.push_back(hash);
	}
}

void SHA::InitializeKeys()
{
	for (int i = 0; i < rounds; i++)
	{
		long double cbroot;
		long double fraction;
		long long int mult = 0;

		switch (version)
		{
		case v256:
		case v224:
			cbroot = cbrt(primes[i]);
			fraction = cbroot - (int)cbroot;
			mult = fraction * pow(2, wordlength);
			break;
		case v512:
		case v384:
			mult = k512[i];
		}

		string key;

		switch (version)
		{
		case v256:
		case v224:
			key = bitset<32>(mult).to_string();
			break;
		case v512:
		case v384:
			key = bitset<64>(mult).to_string();
			break;
		}
		keys.push_back(key);
	}
}

void SHA::ClearStorage()
{
	blocks.clear();
	messageblocks.clear();
}

string SHA::hash(string input)
{
	string digest = "";

	string inputbits;
	InputToBits(&input, &inputbits);
	BitsToBlocks(&inputbits);
	BlocksToMessages();

	string a, b, c, d, e, f, g, h, t1, t2;

	hashes = temphashes;
	for (int i = 0; i < blocks.size(); i++)
	{
		//Initialize Variables
		a = hashes[0];
		b = hashes[1];
		c = hashes[2];
		d = hashes[3];
		e = hashes[4];
		f = hashes[5];
		g = hashes[6];
		h = hashes[7];

		for (int j = 0; j < rounds; j++)
		{

			t1 = BinaryAdd({ h, SummationOne(e), Choose(e,f,g), keys[j], messageblocks[i][j] });
			t2 = BinaryAdd({ SummationZero(a), Majority({a,b,c}) });
			h = g;
			g = f;
			f = e;
			e = BinaryAdd({ d, t1 });
			d = c;
			c = b;
			b = a;
			a = BinaryAdd({ t1,t2 });
		}

		hashes[0] = BinaryAdd({ hashes[0],a });
		hashes[1] = BinaryAdd({ hashes[1],b });
		hashes[2] = BinaryAdd({ hashes[2],c });
		hashes[3] = BinaryAdd({ hashes[3],d });
		hashes[4] = BinaryAdd({ hashes[4],e });
		hashes[5] = BinaryAdd({ hashes[5],f });
		hashes[6] = BinaryAdd({ hashes[6],g });
		hashes[7] = BinaryAdd({ hashes[7],h });
	}

	for (int i = 0; i < hashes.size(); i++)
	{
		//Omit 7th
		if (i == hashes.size() - 1)
		{
			if (version == v224)
				break;
		}
		//Omit 6th and 7th
		if (i == hashes.size() - 2)
		{
			if (version == v384)
				break;
		}

		digest += hashes[i];
	}

	ClearStorage();
	return BinaryToHex(digest);
}
//