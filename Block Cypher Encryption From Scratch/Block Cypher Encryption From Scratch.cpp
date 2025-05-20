#include <iostream>
#include "DES.h"
#include "AES.h"
#include <fstream>
#include <string>

/*
DES:
1) Single DES
2) Triple DES

AES:
1) AES128
2) AES192
3) AES256

Modes Of Encryption (Currently AES Only)
1) ECB
2) CBC
3) OFB (Fastest)
*/

/*
Showcase:
Function: displayEncryption(text): Simply shows all the variants of encryption in ECB mode
Function: encryptDocument(path): Creates an Encrypted and Decrypted version of the document in the "out" folder with AES256
*/

//*WARNING*: Any Character Artifacts Are Due To Different Encoding


void sampleEncryption(string text)
{
	DES des;
	cout << "DES\n\n";

	cout << "Single Encryption\n=================\n\n";
	string key = des.createKey();

	cout << "Original Text: " << text << endl;
	cout << "Key: " << key << endl << endl;
	string encrypted = des.encrypt(text, key);
	cout << "Encrypted Text: " << encrypted << endl;
	string decrypted = des.decrypt(encrypted, key);
	cout << "Decrypted Text: " << decrypted << endl;


	cout << "\nTriple Encryption\n=================\n\n";
	vector<string> keys = des.createTripleKeys();

	cout << "Original Text: " << text << endl;
	cout << "Keys: " << keys[0] << " " << keys[1] << " " << keys[2] << endl << endl;
	encrypted = des.triple_encrypt(text, keys);
	cout << "Encrypted Text: " << encrypted << endl;
	decrypted = des.triple_decrypt(encrypted, keys);
	cout << "Decrypted Text: " << decrypted << endl;

	cout << "\n\n\nAES\n\n";

	AES aes128("128");
	AES aes192("192");
	AES aes256("256");

	string key_128 = aes128.createKey();
	string key_192 = aes192.createKey();
	string key_256 = aes256.createKey();

	string IV = "abcdefghijklmnop";

	cout << "Version :128 Bit\n================\n\n";
	string encrypt = aes128.encrypt(text, key_128);
	string decrypt = aes128.decrypt(encrypt, key_128);
	cout << "Original Text: " << text << endl;
	cout << "Key: " << key_128 << endl << endl;

	cout << "Encrypted Text: " << encrypt << endl;
	cout << "Decrypted Text: " << decrypt << endl;

	cout << "\nVersion :192 Bit\n================\n\n";
	encrypt = aes192.encrypt(text, key_192);
	decrypt = aes192.decrypt(encrypt, key_192);
	cout << "Original Text: " << text << endl;
	cout << "Key: " << key_192 << endl << endl;

	cout << "Encrypted Text: " << encrypt << endl;
	cout << "Decrypted Text: " << decrypt << endl;

	cout << "\nVersion :256 Bit\n================\n\n";
	encrypt = aes256.encrypt(text, key_256);
	decrypt = aes256.decrypt(encrypt, key_256);
	cout << "Original Text: " << text << endl;
	cout << "Key: " << key_256 << endl << endl;

	cout << "Encrypted Text: " << encrypt << endl;
	cout << "Decrypted Text: " << decrypt << endl;

}

void encryptDocument(string path,string key="",string mode="ECB",string IV = "")
{
	//Read From File
	ifstream input(path,ios::binary);
	if (!input.is_open()) {
		cerr << "Error opening the file!";
		return;
	}
	string text;
	string s;
	while (getline(input, s))text += s;
	input.close();


	AES aes256("256",mode);

	if (IV.length() != 16)
		IV = aes256.createKey().substr(0, 16);

	if (key.length() != 32)
		key = aes256.createKey();

	cout << "256 Bit Key: " << key << "\nMode: " << aes256.getMode()<< endl;
	if (mode.compare("ECB"))
		cout << "Initialization Vector: " << IV << endl;

	cout << "\n\nEncrypting..." << endl;

	//Encrypt Data
	string encrypted = aes256.encrypt(text,key,IV);
	ofstream encryptoutput("../out/encrypted.txt");
	if (!encryptoutput.is_open()) {
		cerr << "Error writing the encryption!";
		return;
	}
	encryptoutput << encrypted;
	encryptoutput.close();
	
	cout << "\nEncryption Done!\n"<<endl;

	cout << "Decrypting..." << endl;
	//Decrypt Data
	string decrypted = aes256.decrypt(encrypted, key,IV);
	ofstream decryptoutput("../out/decrypted.txt",ios::binary);
	if (!decryptoutput.is_open()) {
		cerr << "Error writing the decryption!";
		return;
	}

	decryptoutput << decrypted;
	decryptoutput.close();

	cout << "\nDecryption Done!" << endl;
}

int main()
{
	//Any 32 letter key, 16 letter IV will work
	
	encryptDocument("../sample.txt");
	//encryptDocument("../sample.txt","abcdefghijklmnopqrstuvwx12345678","ECB");
	//encryptDocument("../sample.txt","abcdefghijklmnopqrstuvwx12345678","OFB");
	//encryptDocument("../sample.txt","abcdefghijklmnopqrstuvwx12345678","CBC");
	//encryptDocument("../sample.txt","abcdefghijklmnopqrstuvwx12345678","OFB","abcdefghijklmnop");
	//encryptDocument("../sample.txt","abcdefghijklmnopqrstuvwx12345678","CBC","abcdefghijklmnop");

}