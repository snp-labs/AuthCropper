#include<iostream>
#include<opencv2/imgproc/imgproc.hpp>
#include<opencv2/highgui/highgui.hpp>
#include<opencv2/opencv.hpp>
#include<time.h>
#include<stdlib.h>
#include <cstring>
#include <fstream>
#include "sha256.h"
#include<vector>
#include<string.h>
#include<bitset>
#include<ctime>
#include<cstdlib>
#include<vector>
#include"untrusted.h"

using namespace std;
using namespace cv;


string EncKey(string lx, string ly, string rx, string ry);
Mat Encryption_Matrix(Mat src, string* LxKey, string* RxKey, string* LyKey, string* RyKey, int M, int N, int BlockSize);
string* Create_EncKey(int length, string KEY);
string Create_Specific_Location_Key_R(string Msk, int Location, int Length);
string Create_Specific_Location_Key_L(string Msk, int Location);
string* CropKeyGen(int M, int N, int Left_M, int Left_N, int Right_M, int Right_N, string Lx_Msk, string Ly_Msk, string Rx_Msk, string Ry_Msk);
Mat Decryption(Mat EncSrc, int M, int N, string* DecKeyGroup, int BlockSize, int Left_M, int Left_N, int Right_M, int Right_N);
string HexToASCII(string hex);
string EncKey(string lx, string ly, string rx, string ry);



#pragma region Ű �迭 �����ϴ� ��


string* Create_EncKey(int length, string KEY) {
	string *Key = new string[length];
	Key[0] = sha256(KEY);
	for (int i = 1; i < length; i++) Key[i] = sha256(Key[i - 1]);

	return Key;
}
string* Create_EncKey_Sub(int length,string KEY){
	string* Key = new string[length];
	Key[0] = KEY;
	for(int i=1;i<length;i++)
		Key[i] = sha256(Key[i-1]);

	return Key;
}
#pragma endregion

#pragma region Dec Key 
string Create_Specific_Location_Key_L(string Msk, int Location) {
	string Spec_key = sha256(Msk); // Lx_Key[0] , Ly_Key[0]
	for (int i = 0; i < Location; i++) Spec_key = sha256(Spec_key);

	return Spec_key;
}

string Create_Specific_Location_Key_R(string Msk, int Location, int Length) {
	string Spec_key = sha256(Msk); // Rx_Key[0]
	for (int i = 1; i <Length - Location; i++) 	Spec_key = sha256(Spec_key);

	return Spec_key;
}
#pragma endregion

// Decryption
string* CropKeyGen(int M, int N, int Left_M, int Left_N, int Right_M, int Right_N , string Lx_Msk , string Ly_Msk,string Rx_Msk, string Ry_Msk) {
	string* DecKeyGroup = new string[4];
	DecKeyGroup[0] = Create_Specific_Location_Key_L(Lx_Msk, Left_N); //  Lx
	DecKeyGroup[1] = Create_Specific_Location_Key_L(Ly_Msk, Left_M); // Ly
	DecKeyGroup[2] = Create_Specific_Location_Key_R(Rx_Msk, Right_N,N); // Rx
	DecKeyGroup[3] = Create_Specific_Location_Key_R(Ry_Msk, Right_M,M); // Ry

	cout << "LX_KEY : " << DecKeyGroup[0] << endl;
	cout << "LY_KEY : " << DecKeyGroup[1] << endl;
	cout << "RX_KEY : " << DecKeyGroup[2] << endl;
	cout << "RY_KEY : " << DecKeyGroup[3] << endl;

	return DecKeyGroup;
}

Mat Decryption(Mat EncSrc, int M, int N, string* DecKeyGroup, int BlockSize, int Left_M, int Left_N, int Right_M, int Right_N) {
	Mat DecSrc = EncSrc.clone();
	string* Dec_LxKey, *Dec_LyKey, *Dec_RxKey, *Dec_RyKey;
	/*
		ex.
		M : 10 N : 18
		Left_N : 0 , Left_M : 0
		Right_N : 6 , Right_M : 5
	*/
	Dec_LxKey = Create_EncKey_Sub(Right_N-Left_N+1, DecKeyGroup[0]); // Dec_LxKey : 18 - 0 = 18
	Dec_LyKey = Create_EncKey_Sub(Right_M-Left_M+1, DecKeyGroup[1]); // Dec_LxKey : 10 - 0 = 10
	Dec_RxKey = Create_EncKey_Sub(Right_N-Left_N+1,DecKeyGroup[2]);
	Dec_RyKey = Create_EncKey_Sub(Right_M-Left_M+1, DecKeyGroup[3]); // Dec_LxKey :  5
	
	for (int i = 0; i < Right_M-Left_M+1; i++) { 
		for (int j = 0; j < Right_N-Left_N+1; j++) { 
			int count = 0;
			string EncKeyData = EncKey(Dec_LxKey[j], Dec_LyKey[i], Dec_RxKey[(Right_N-Left_N) - j], Dec_RyKey[(Right_M-Left_M) - i]);
			for (int row = 0; row < BlockSize; row++) {
				for (int col = 0; col < BlockSize; col++) {
					DecSrc.at<uchar>(((BlockSize*(Left_M + i)) + row), ((BlockSize*(Left_N + j)) + col)) ^= EncKeyData[count];
					count++;
				}
			}
			
		}
	}
	return DecSrc;
}

//Hex string to ASCII string
string HexToASCII(string hex)
{
	int len = hex.length();
	std::string newString;
	for (int i = 0; i< len; i += 2)
	{
		string byte = hex.substr(i, 2);//
		char chr = (char)(int)strtol(byte.c_str(), NULL, 16);
		newString += chr; 
	}
	return newString;
}


string EncKey(string lx, string ly, string rx, string ry) {
	std::string key = lx+ly+rx+ry;
	const char* index = "01234567";
	std::string tempKey="";
	for(int i=0;i<8;i++)
		tempKey += sha256(key+index[i]);
	
	string EncKey = HexToASCII(tempKey); 

	return EncKey;
}


Mat Encryption_Matrix(Mat src,string* LxKey,string* RxKey,string* LyKey,string* RyKey,int M,int N,int BlockSize) {
	Mat EncMat = src.clone(); 
	
		for (int m = 0; m < M; m++) {
			for (int n = 0; n < N; n++) { 
				string BlockData = ""; 
				for (int i = 0; i < BlockSize; i++) {
					for (int j = 0; j < BlockSize; j++) 
						BlockData += src.at<uchar>((BlockSize * m) + i, (BlockSize * n) + j);
				}
				
				string EncKeyData = EncKey(LxKey[n], LyKey[m], RxKey[N - n-1], RyKey[M - m-1]);
				int count = 0;
				for (int block_row = 0; block_row < BlockSize; block_row++) {
					for (int block_col = 0; block_col < BlockSize; block_col++) {
						EncMat.at<uchar>((BlockSize * m) + block_row, (BlockSize * n) + block_col) = BlockData[count] ^ EncKeyData[count];// XOR
						count++;
					}
				}
			}
		} 
	return EncMat;
}

int main(int argc,char** argv)
{
	if(argc !=2)
	{
		cout<<"error"<<endl;
		return -1;
	}


	char Lx_arr[32] = { "AK12rsc9320dkcvc9d02k2d2j230dkC" };
	char Ly_arr[32] = { "dfldje230idkdvj39wodkdjv023kfjk" };
	char Rx_arr[32] = { "sdfj3k2d9fslkgadkjSDEdvkej23l9c" };
	char Ry_arr[32] = { "DJflkf320fdkvj12e1lkvcv9woq3kzd" };

	Mat src,dst,Dec;
	const int BlockSize = 16;
	int M, N;
	int Left_N, Left_M , Right_N,Right_M;
	//for Mat to str
	Size size;
	int total;
	//for signature
	int i, isVerify;
	char *str;

	cout<<"argv[1] : "<<argv[1]<<endl;

	/// Load an image
	src = imread(argv[1], CV_LOAD_IMAGE_GRAYSCALE);
	M = src.rows / BlockSize; // 
	N = src.cols / BlockSize; //
	cout << "Row of block matrix - M : " << M << endl << "Column of block matrix- N : "<< N << endl<<endl;
	cout << "Row of src - M' : " << src.rows << endl << "Column of src : " << src.cols << endl << endl;
	if (!src.data)
	{
		return -1;
	}
	size = src.size();
	total = size.width * size.height * src.channels();	
	cout<<"size of src is "<<size<<endl;
	cout<<"total is "<<total<<endl;
	
	cout << "LX, LY, RX , RY create" << endl;
	string* Lx_key = Create_EncKey(N,Lx_arr);
	string* Ly_key = Create_EncKey(M,Ly_arr);
	string* Rx_key = Create_EncKey(N,Rx_arr);
	string* Ry_key = Create_EncKey(M,Ry_arr);

	cout << "Lx_Key[0] : " <<Lx_key[0] << endl;
	cout << "Ly_Key[0] : " << Ly_key[0] << endl;
	cout << "Rx_Key[0] : " << Rx_key[0] << endl;
	cout << "Ry_Key[0] : " << Ry_key[0] << endl;
	
#pragma region Encryption �κ�
	cout << "Encryption " << endl<<endl;
	dst = Encryption_Matrix(src, Lx_key, Rx_key, Ly_key, Ry_key,M,N,BlockSize);
	imwrite("Enc_uhd_test_Block16.jpeg", dst);
	uchar_t *data = src.data;
	 
	cout << "Encryption " << endl<<endl;
#pragma endregion

#pragma region signature setup

	message_t msg;
	msg->data = data;
	msg->length =50400;// strlen(msg->data);
	//msg->length = msg->data.size();
	pairing_t pairing;
	vk_t vk;
	encsk_t encsk;
	//deck_t deck;
	sigma_t sigma;

	timePeriod_t next;

	keygenTime = 0;
	updateTime = 0;
	signTime = 0;
	verifyTime = 0;

	setup(pairing);
	keyGen(kL, kM, vk, encsk, pairing);
	checkKey(encsk, vk, pairing);

#pragma endregion

#pragma region signature sign

	sign(sigma, msg, encsk, vk, pairing);
	isVerify = verify(sigma, msg, vk, pairing);

	int sksize=sizeof(encsk);
	int pksize=sizeof(vk);
	int sigsize=sizeof(sigma);
	fprintf(stdout,"secret Key size  is = %d\n",sksize);
	fprintf(stdout,"public Key size  is = %d\n",pksize);
	fprintf(stdout,"signature Key size  is = %d\n",sigsize);

	//free(next->data);

	printf("\n\n=================================\n");
	printf("=================================\n");
	printf("=================================\n");
	printf("keygen: %g\n", keygenTime);
	printf("update: %g\n", updateTime*0.2);
	printf("sign: %g\n", signTime*0.5);
	printf("verify: %g\n", verifyTime*0.5);

#pragma endregion


#pragma region Decryption �κ�
	cout << "Decryption" << endl << "Decryption range"<<endl<<"(ex."<<"0 0 "<<M<<" "<<N<<" M'>M and N'>N)" << endl;

	cin >> Left_M >> Left_N >> Right_M >> Right_N;

	cout << "CropKeyGen start" << endl;
	string* DecKey = CropKeyGen(M, N,Left_M, Left_N, Right_M, Right_N, Lx_arr, Ly_arr, Rx_arr, Ry_arr);
	cout << "CropKeyGen terminated" << endl;
	cout << "Decryption start" << endl;
	Dec = Decryption(dst, M, N, DecKey, BlockSize, Left_M, Left_N, Right_M, Right_N);
	cout << "Decryption terminated" << endl;
	imwrite("Dec_uhd_test_Block16.jpeg", Dec);
#pragma endregion

	return 0;
}


