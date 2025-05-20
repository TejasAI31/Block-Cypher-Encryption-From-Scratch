#include "DES.h"

DES::DES()
{
	srand(time(NULL));
}

string DES::createKey()
{
	static SHA sha256("256");
	return sha256.hash(to_string(rand())).substr(0, 8);
}

vector<string> DES::createTripleKeys()
{
	static SHA sha256("256");
	vector<string> triplekey;
	for (int i = 0; i < 3; i++)
	{
		triplekey.push_back(sha256.hash(to_string(rand())).substr(0, 8));
	}
	return triplekey;
}

string DES::LOTR(string input, int shift)
{
	return input.substr(shift, input.length() - shift) + input.substr(0, shift);
}

string DES::compressKey(string input)
{
	string compressedkey = "";
	for (int i = 0; i < Key_Compression.size(); i++)
		compressedkey += input[Key_Compression[i]-1];
	return compressedkey;
}

void DES::initializeRoundKeys(string key, int inverse)
{
	string bigkey = "";
	for (int i = 0; i < key.length(); i++)
		bigkey += bitset<8>(key[i]).to_string();

	string bitkey = "";
	for (int i = 0; i < bigkey.size(); i++)
	{
		if ((i + 1) % 8 != 0)
			bitkey += bigkey[i];
	}

	string lkey = bitkey.substr(0, 28);
	string rkey = bitkey.substr(28, 28);


	int specround_counter = 0;
	for (int i = 0; i < rounds; i++)
	{
		if (i + 1 == Special_Rounds[specround_counter])
		{
			lkey = LOTR(lkey, 1);
			rkey = LOTR(rkey, 1);
			specround_counter++;
		}
		else
		{
			lkey = LOTR(lkey, 2);
			rkey = LOTR(rkey, 2);
		}

		string joinedkey = lkey + rkey;
		string compressedkey = compressKey(joinedkey);
		
		keys.push_back(compressedkey);
	}

	if (inverse==1)
		reverse(keys.begin(), keys.end());


}

void DES::bitsToBlocks(string input)
{
	for (int i = 0; i < input.length(); i += 64)
		blocks.push_back(input.substr(i, 64));
}

string DES::inputToBits(string input)
{
	string bits = "";

	for (int i = input.length(); i < 8 * ceil(input.length() / (float)8); i++)
		input += '\0';

	for (int i = 0; i < input.size(); i++)
		bits += bitset<8>(input[i]).to_string();

	return bits;
}

string DES::initialPermute(string input)
{
	string permuted = "";
	for (int i = 0; i < IP.size(); i++)
		permuted += input[IP[i]-1];
	return permuted;
}

string DES::finalPermute(string input)
{
	string permuted = "";
	for (int i = 0; i < IP_Inverse.size(); i++)
		permuted += input[IP_Inverse[i]-1];
	return permuted;
}

string DES::rightExpansion(string input)
{
	string expanded = "";
	for (int i = 0; i < Expansion.size(); i++)
		expanded += input[Expansion[i]-1];
	return expanded;
}

string DES::XOR(string a, string b)
{
	string out = "";
	for (int i = 0; i < a.length(); i++)
	{
		if (a[i] == b[i])
			out += '0';
		else
			out += '1';
	}
	return out;
}

int DES::bitToInt(string input)
{
	int output = 0;
	int counter = 0;
	for (int i = input.length() - 1; i >= 0; i--)
	{
		if (input[i] == '1')
			output += pow(2, counter);
		counter++;
	}
	return output;
}

string DES::sbox(string input)
{
	string out = "";
	
	string sixbit;
	int counter = 0;
	for (int i = 0; i < input.size(); i += 6)
	{
		sixbit = input.substr(i, 6);
		out += bitset<4>(SBoxes[counter][bitToInt(to_string(sixbit[0]) + to_string(sixbit[5]))][bitToInt(sixbit.substr(1, 4))]).to_string();
		counter++;
	}

	return out;
}

string DES::pbox(string input)
{
	string out = "";
	for (int i = 0; i < PBox.size(); i++)
	{
		out += input[PBox[i]-1];
	}
	return out;
}

string DES::bitToChar(string input)
{
	string finalstr = "";

	for (int i = 0; i < input.size(); i += 8)
		finalstr += bitToInt(input.substr(i, 8));
	return finalstr;
}

void DES::clearStorage()
{
	keys.clear();
	blocks.clear();
}

string DES::feistel(string input, string key, int rev)
{
	string encrypted = "";

	initializeRoundKeys(key, rev);
	bitsToBlocks(inputToBits(input));

	string permuted;
	string ltext;
	string rtext;
	string expanded_rtext;
	string inputkey_xor;
	string sboxout;
	string pboxout;
	string newrtext;

	for(int i=0;i<blocks.size();i++)
	{
		permuted = initialPermute(blocks[i]);

		ltext = permuted.substr(0, 32);
		rtext = permuted.substr(32, 32);

		for (int j = 0; j < rounds; j++)
		{
			expanded_rtext = rightExpansion(rtext);
			inputkey_xor = XOR(expanded_rtext, keys[j]);
			sboxout = sbox(inputkey_xor);
			pboxout = pbox(sboxout);

			newrtext = XOR(pboxout, ltext);

			ltext = rtext;
			rtext = newrtext;
		}

		encrypted+=finalPermute(rtext + ltext);
	}
	
	clearStorage();
	return bitToChar(encrypted);
}

string DES::decrypt(string input, string key)
{
	string decrypted=feistel(input, key, 1);
	string out="";
	
	for (int i = 0; i < decrypted.length(); i ++)
	{
		if (decrypted[i] == '\0')
			break;
		out+=decrypted[i];
	}
	return out;
}

string DES::encrypt(string input, string key)
{
	return feistel(input, key, 0);
}

string DES::triple_decrypt(string input, vector<string> keys)
{
	if (keys.size() < 3)
		return "";

	string decrypted = input;
	for (int i = 2; i >=0; i--)
	{
		decrypted=feistel(decrypted, keys[i], 1);
	}

	string out = "";

	for (int i = 0; i < decrypted.length(); i++)
	{
		if (decrypted[i] == '\0')
			break;
		out += decrypted[i];
	}
	return out;
}

string DES::triple_encrypt(string input, vector<string> keys)
{
	string encrypted=input;
	if (keys.size() < 3)
		return "";

	for (int i = 0; i < 3; i++)
	{
		encrypted=feistel(encrypted, keys[i], 0);
	}

	return encrypted;
}
//