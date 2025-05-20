#include "AES.h"

//Constructor
AES::AES(string variant,string encryptmode)
{
	if (!variant.compare("128"))
	{
		type = v128;
		wordnum = 4;
		rounds = 10;
	}
	else if (!variant.compare("192"))
	{
		type = v192;
		wordnum = 6;
		rounds = 12;
	}
	else if (!variant.compare("256"))
	{
		type = v256;
		wordnum = 8;
		rounds = 14;
	}

	if (!encryptmode.compare("ECB"))
		mode = ECB;
	else if (!encryptmode.compare("CBC"))
		mode = CBC;
	else if (!encryptmode.compare("OFB"))
		mode = OFB;

	return;
}

//Working Functions
string AES::LShift(string input, int shift)
{
	string out = input.substr(shift, input.length() - shift);
	for (int i = 0; i < shift; i++)
		out += '0';
	return out;
}

void AES::bitsToBlocks(string input)
{
	for (int i = 0; i < input.length(); i += 128)
		blocks.push_back(input.substr(i, 128));
}

string AES::inputToBits(string input)
{
	string bits = "";

	for (int i = input.length(); i < 16 * ceil(input.length() / (float)16); i++)
		input += '\0';

	for (int i = 0; i < input.size(); i++)
		bits += bitset<8>(input[i]).to_string();

	return bits;
}

string AES::XOR(string a, string b)
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

string AES::vectorXOR(vector<string>& inputs)
{
	string out;
	for (int i = 0; i < inputs[0].size(); i++)
	{
		int sum = 0;
		for (int j = 0; j < inputs.size(); j++)
		{
			sum += inputs[j][i] - 48;
		}
		out += 48 + sum % 2;
	}
	return out;
}

int AES::bitToInt(string input)
{
	int output = 0;
	int counter = 0;
	for (int i = input.length() - 1; i >= 0; i--)
	{
		if (input[i] == '1')
			output += (int)pow(2, counter);
		counter++;
	}
	return output;
}

string AES::bitToChar(string input)
{
	string finalstr = "";

	for (int i = 0; i < input.size(); i += 8)
		finalstr += bitToInt(input.substr(i, 8));
	return finalstr;
}

void AES::initializeRoundConstants()
{
	vector <long long unsigned int> rc = {1};
	round_constants.push_back(bitset<8>(1).to_string());

	for (int i = 1; i < rounds; i++)
	{
		if (rc[i - 1] < 128)
		{
			rc.push_back(rc[i - 1] * 2);
			round_constants.push_back(bitset<8>(rc[i - 1] * 2).to_string());
		}
		else
		{
			round_constants.push_back(XOR(bitset<12>(rc[i - 1] * 2).to_string(), "000100011011").substr(4,8));
			rc.push_back(bitToInt(round_constants.back()));
		}
	}
}

string AES::sbox(string input,bool rev=false)
{
	int row = bitToInt(input.substr(0, 4));
	int column = bitToInt(input.substr(4, 4));
	
	string s;
	if(!rev)
		s=SBox[row][column];
	else
		s = inverse_SBox[row][column];

	string sub = "";

	for (int i = 0; i <=1; i++)
	{
		if (isalpha(s[i]))
			sub += bitset<4>(s[i] - 87).to_string();
		else
			sub += bitset<4>(s[i] - 48).to_string();
	}

	return sub;
}

void AES::initializeRoundKeys(string input)
{
	initializeRoundConstants();

	string key = "";
	for (int i = 0; i < input.length(); i++)
		key += bitset<8>(input[i]).to_string();
	
	vector<string> bytes;
	for (int i = 0; i < key.length(); i += 8)
		bytes.push_back(key.substr(i, 8));

	//Create Key Matrices
	for (int i = 0; i < 4; i++)
	{
		vector<string> row(4 * rounds + 4);
		keys.push_back(row);
	}
	
	//Keys
	for (int i = 0; i < 4*rounds+4; i++)
	{
		//CASE 1
		if (i < wordnum)
		{
			for (int j = 0; j < 4; j++)
				keys[j][i] = bytes[i * 4 + j];
		}

		//CASE 2
		else if (i>=wordnum&&i%wordnum==0)
		{
			vector<string> rot;
			vector<string> last;
			for (int j = 0; j < 4; j++)
			{
				rot.push_back(sbox(keys[j][i-1]));
				last.push_back(keys[j][i - wordnum]);
			}
			string temp = rot[0];
			for (int j = 0; j < 3; j++)
			{
				rot[j] = rot[j + 1];
			}
			rot[3] = temp;

			for (int j = 0; j < 4; j++)
			{
				if (j == 0)
				{
					keys[j][i] = XOR(XOR(rot[j], last[j]), round_constants[(i / wordnum)-1]);
				}
				else
				{
					keys[j][i] = XOR(rot[j], last[j]);
				}
			}
		}

		//CASE 3 (256 bit only)
		else if (i>=wordnum&&wordnum>6&&i%wordnum==4)
		{
			for (int j = 0; j < 4; j++)
			{
				keys[j][i] = XOR(sbox(keys[j][i - 1]), keys[j][i - wordnum]);
			}
		}

		//CASE 4
		else
		{
			for (int j = 0; j < 4; j++)
			{
				keys[j][i] = XOR(keys[j][i - 1], keys[j][i - wordnum]);
			}
		}

	}
}

void AES::arrangeBlock(string input,vector<vector<string>>& block)
{
	for (int i = 0; i < 4; i++)
	{
		vector<string> row(4);
		block.push_back(row);
	}

	int counter = 0;
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			block[j][i] = input.substr(counter, 8);
			counter += 8;
		}
	}

	return;
}

void AES::blockXOR(vector<vector<string>>& block, int round)
{

	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			block[i][j] = XOR(block[i][j], keys[i][j + round * 4]);
		}
	}
	return;
}

void AES::byteSubstitution(vector<vector<string>>& block,bool rev=false)
{
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			block[i][j] = sbox(block[i][j],rev);
		}
	}
	return;
}

string AES::Mod8(string input)
{
	if (input[0] == '1')
		return XOR(input.substr(1, 8), irred_poly);
	else
		return input.substr(1, 8);
}

void AES::shiftRows(vector<vector<string>>& block)
{
	for (int j = 1; j < 4; j++)
	{
		vector<string> temp;
		for (int k = 0; k < j; k++)
		{
			temp.push_back(block[j][k]);
		}
		for (int k = 0; k < 4 - j; k++)
		{
			block[j][k] = block[j][k + j];
		}

		short int counter = 0;
		for (int k = 4 - j; k < 4; k++)
		{
			block[j][k] = temp[counter];
			counter++;
		}
	}
	return;
}

void AES::shiftRowsInverse(vector<vector<string>>& block)
{
	for (int j = 1; j < 4; j++)
	{
		vector<string> temp;
		for (int k = 4-j; k < 4; k++)
		{
			temp.push_back(block[j][k]);
		}
		for (int k = 3; k >= j; k--)
		{
			block[j][k] = block[j][k-j];
		}

		short int counter = 0;
		for (int k = 0; k < j; k++)
		{
			block[j][k] = temp[counter];
			counter++;
		}
	}
	return;
}

void AES::mixColumns(vector<vector<string>>& block)
{
	vector<vector<string>> out;
	for (int i = 0; i < 4; i++)
	{
		vector<string> temp(4);
		out.push_back(temp);
	}

	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			string base = "00000000";
			for (int k = 0; k < 4; k++)
			{
				switch (MixCols[i][k])
				{
				case 1:
					base = XOR(base, block[k][j]);
					break;
				case 2:
					base = XOR(base, Mod8(LShift("0"+block[k][j], 1)));
					break;
				case 3:
					base = XOR(base, XOR(block[k][j], Mod8(LShift("0" + block[k][j], 1))));
					break;
				}
			}

			out[i][j] = base;
		}
	}

	block = out;
	return;
}

string AES::galoisMod8(string input)
{
	int lindex = 0;

	for (int i = 0; i < input.size(); i++)
	{
		if (input[i] == '1')
		{
			lindex = i;
			break;
		}
	}

	if (lindex > 6)
		return input.substr(7,8);
	
	while (lindex < 7)
	{
		input = XOR(input, LShift(irred_poly_15, 6-lindex));

		bool flag = false;
		for (int i = 0; i < input.size(); i++)
		{
			if (input[i] == '1')
			{
				lindex = i;
				flag = true;
				break;
			}
		}
		if (!flag)
			lindex = input.size()-1;
	}

	return input.substr(7,8);
}

string AES::galoisMult(string a, string b)
{
	vector<string> multiples;
	int l = b.length()-1;
	for (int i = 0; i < b.length(); i++)
	{
		if (b[l - i] == '1')
			multiples.push_back(LShift(a, i));
	}

	if (multiples.size() == 0)
	{
		string out = "";
		for (int i = 0; i < b.length(); i++)
			out += '0';
		return out;
	}
	else
		return vectorXOR(multiples);
}

void AES::mixColumnsInverse(vector<vector<string>>& block)
{
	vector<vector<string>> out;
	for (int i = 0; i < 4; i++)
	{
		vector<string> temp(4);
		out.push_back(temp);
	}

	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			string base = "000000000000000";
			for (int k = 0; k < 4; k++)
			{
				base = XOR(base, galoisMult(MixColsInverse[i][k],"0000000"+block[k][j]));
			}

			out[i][j] = galoisMod8(base);
		}
	}

	block = out;
	return;
}

string AES::ivToBits(string input)
{
	string out = "";
	for (int i = 0; i < input.size(); i++)
		out += bitset<8>(input[i]).to_string();

	return out;
}

string AES::getMode()
{
	switch (mode)
	{
	case ECB:
		return "ECB";
	case CBC:
		return "CBC";
	case OFB:
		return "OFB";
	}
	return "ERROR";
}

//Main Functions
void AES::clear()
{
	blocks.clear();
	keys.clear();
	round_constants.clear();
}

string AES::createKey()
{
	string key;
	SHA hasher("256");

	switch (type)
	{
	case v128:
		key = hasher.hash(to_string(rand())).substr(0, 16);
		break;
	case v192:
		key = hasher.hash(to_string(rand())).substr(0, 24);
		break;
	case v256:
		key= key = hasher.hash(to_string(rand())).substr(0, 32);
		break;
	}
	return key;
}

void AES::electronicCodeBook(string& out)
{
	for (int b = 0; b < blocks.size(); b++)
	{
		//Arranging Block In 4X4 bytes
		vector<vector<string>> block;
		arrangeBlock(blocks[b],block);

		//Initial XOR
		blockXOR(block, 0);

		//Rounds
		for (int round = 1; round <= rounds; round++)
		{
			byteSubstitution(block);
			shiftRows(block);

			if (round != rounds)
				mixColumns(block);

			blockXOR(block, round);
		}

		//Adding Output
		for (int i = 0; i < 4; i++)
		{
			for (int j = 0; j < 4; j++)
			{
				out += block[j][i];
			}
		}
	}
}

void AES::electronicCodeBookDecrypt(string& out)
{
	for (int b = 0; b < blocks.size(); b++)
	{
		//Arranging Block In 4X4 bytes
		vector<vector<string>> block;
		arrangeBlock(blocks[b],block);

		//Initial XOR
		blockXOR(block, rounds);

		//Rounds
		for (int round = 1; round <= rounds; round++)
		{
			shiftRowsInverse(block);
			byteSubstitution(block, true);

			blockXOR(block, rounds - round);

			if (round != rounds)
				mixColumnsInverse(block);

		}

		//Adding Output
		for (int i = 0; i < 4; i++)
		{
			for (int j = 0; j < 4; j++)
			{
				out += block[j][i];
			}
		}
	}
}

void AES::cipherBlockChaining(string& out, string IV)
{
	if (IV.length() != 16)
	{
		cout << "IV Length Not Valid\n";
		return;
	}

	IV = ivToBits(IV);
	
	vector<string> encryptedBlocks;

	for (int b = 0; b < blocks.size(); b++)
	{
		if (b == 0)
			blocks[b] = XOR(blocks[b], IV);
		else
			blocks[b] = XOR(blocks[b], encryptedBlocks.back());

		//Arranging Block In 4X4 bytes
		vector<vector<string>> block;
		arrangeBlock(blocks[b], block);

		//Initial XOR
		blockXOR(block, 0);

		//Rounds
		for (int round = 1; round <= rounds; round++)
		{
			byteSubstitution(block);
			shiftRows(block);

			if (round != rounds)
				mixColumns(block);

			blockXOR(block, round);
		}

		//Adding Output
		string encrypted = "";
		for (int i = 0; i < 4; i++)
		{
			for (int j = 0; j < 4; j++)
			{
				encrypted += block[j][i];
			}
		}
		encryptedBlocks.push_back(encrypted);
	}

	for (int i = 0; i < encryptedBlocks.size(); i++)
		out += encryptedBlocks[i];
}

void AES::cipherBlockChainingDecrypt(string& out, string IV)
{
	if (IV.length() != 16)
	{
		cout << "IV Length Not Valid\n";
		return;
	}

	IV = ivToBits(IV);

	vector<string> decryptedBlocks;

	for (int b = 0; b < blocks.size(); b++)
	{
		//Arranging Block In 4X4 bytes
		vector<vector<string>> block;
		arrangeBlock(blocks[b],block);

		//Initial XOR
		blockXOR(block, rounds);

		//Rounds
		for (int round = 1; round <= rounds; round++)
		{
			shiftRowsInverse(block);
			byteSubstitution(block, true);

			blockXOR(block, rounds - round);

			if (round != rounds)
				mixColumnsInverse(block);

		}			

		//Adding Output
		string decrypted = "";
		for (int i = 0; i < 4; i++)
		{
			for (int j = 0; j < 4; j++)
			{
				decrypted += block[j][i];
			}
		}

		if (b == 0)
			decrypted = XOR(decrypted, IV);
		else
			decrypted = XOR(decrypted, blocks[b-1]);

		decryptedBlocks.push_back(decrypted);
	}

	for (int i = 0; i < decryptedBlocks.size(); i++)
		out += decryptedBlocks[i];


}

void AES::outputFeedbackMode(string& out, string IV)
{
	if (IV.length() != 16)
	{
		cout << "IV Length Not Valid\n";
		return;
	}

	IV = ivToBits(IV);

	vector<vector<string>> block;
	arrangeBlock(IV,block);

	for (int b = 0; b < blocks.size(); b++)
	{
		//Initial XOR
		blockXOR(block, 0);

		//Rounds
		for (int round = 1; round <= rounds; round++)
		{
			byteSubstitution(block);
			shiftRows(block);

			if (round != rounds)
				mixColumns(block);

			blockXOR(block, round);
		}

		//Adding Output
		string encrypted = "";
		for (int i = 0; i < 4; i++)
		{
			for (int j = 0; j < 4; j++)
			{
				encrypted += block[j][i];
			}
		}

		out += XOR(encrypted, blocks[b]);
	}
}

void AES::outputFeedbackModeDecrypt(string& out, string IV)
{
	if (IV.length() != 16)
	{
		cout << "IV Length Not Valid\n";
		return;
	}

	IV = ivToBits(IV);

	vector<vector<string>> block;
	arrangeBlock(IV,block);

	for (int b = 0; b < blocks.size(); b++)
	{
		//Initial XOR
		blockXOR(block, 0);

		//Rounds
		for (int round = 1; round <= rounds; round++)
		{
			byteSubstitution(block);
			shiftRows(block);

			if (round != rounds)
				mixColumns(block);

			blockXOR(block, round);
		}

		//Adding Output
		string decrypted = "";
		for (int i = 0; i < 4; i++)
		{
			for (int j = 0; j < 4; j++)
			{
				decrypted += block[j][i];
			}
		}

		out += XOR(decrypted, blocks[b]);
	}
}

string AES::decrypt(string input, string key,string IV)
{
	if (key.length() != 16 && key.length() != 24 && key.length() != 32)
		return "Key Size Not Applicable";

	bitsToBlocks(inputToBits(input));
	initializeRoundKeys(key);

	string decrypted = "";

	switch (mode)
	{
	case ECB:
		electronicCodeBookDecrypt(decrypted);
		break;
	case CBC:
		cipherBlockChainingDecrypt(decrypted, IV);
		break;
	case OFB:
		outputFeedbackModeDecrypt(decrypted, IV);
		break;
	}
	
	clear();
	string out= bitToChar(decrypted);

	for (int i = out.length()-1; i >= 0; i--)
	{
		if (out[i] != '\0')
		{
			if(i!=out.length()-1)
				out.erase(i+1);
			break;
		}
	}

	return out;
}

string AES::encrypt(string input,string key,string IV)
{
	if (key.length() != 16 && key.length() != 24 && key.length() != 32)
		return "Key Size Not Applicable";

	bitsToBlocks(inputToBits(input));
	initializeRoundKeys(key);

	string encrypted = "";

	switch (mode)
	{
	case ECB:
		electronicCodeBook(encrypted);
		break;
	case CBC:
		cipherBlockChaining(encrypted, IV);
		break;
	case OFB:
		outputFeedbackMode(encrypted, IV);
		break;
	}

	clear();
	return bitToChar(encrypted);
}

//