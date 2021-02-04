#include<iostream>
#include<opencv2/imgproc/imgproc.hpp>
#include<opencv2/highgui/highgui.hpp>
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
//#include "untrusted.h"

using namespace std;
using namespace cv;

typedef unsigned char uchar_t;


string random_string(size_t length);
string EncKey(string lx, string ly, string rx, string ry);

Mat Encryption_Matrix(Mat src, string* LxKey, string* RxKey, string* LyKey, string* RyKey, int M, int N, int BlockSize);
string* Create_EncKey(int length, string KEY);
string Create_Specific_Location_Key_R(string Msk, int Location, int Length);
string Create_Specific_Location_Key_L(string Msk, int Location);
string* CropKeyGen(int M, int N, int Left_M, int Left_N, int Right_M, int Right_N, string Lx_Msk, string Ly_Msk, string Rx_Msk, string Ry_Msk);
Mat Decryption(Mat EncSrc, int M, int N, string* DecKeyGroup, int BlockSize, int Left_M, int Left_N, int Right_M, int Right_N);
string HexToASCII(string hex);
string EncKey(string lx, string ly, string rx, string ry);


string random_string(size_t length)
{
	auto randchar = []() -> char //generator를 만든 곳
	{
		const char charset[] =
			"0123456789"
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			"abcdefghijklmnopqrstuvwxyz";
		const size_t max_index = (sizeof(charset) - 1);
		return charset[rand() % max_index];
	};
	string random_str(length, 0);
	std::generate_n(random_str.begin(), length, randchar);
	return random_str;
}

#pragma region 키 배열 생성하는 곳


string* Create_EncKey(int length, string KEY) {
	string *Key = new string[length];
	Key[0] = sha256(KEY);
	for (int i = 1; i < length; i++) Key[i] = sha256(Key[i - 1]);

	return Key;
}
string* Create_EncKey_sub(int length, string KEY) {
	string *Key = new string[length];
	Key[0] = KEY;
	for (int i = 1; i < length; i++) Key[i] = sha256(Key[i - 1]);

	return Key;
}
#pragma endregion

#pragma region Dec Key 배열 만들 때 만든 함수


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

// In this function, designate scope(rectangle) 
string* CropKeyGen(int M, int N, int Left_M, int Left_N, int Right_M, int Right_N , string Lx_Msk , string Ly_Msk,string Rx_Msk, string Ry_Msk) {
	string* DecKeyGroup = new string[4];
	DecKeyGroup[0] = Create_Specific_Location_Key_L(Lx_Msk, Left_N); 
	DecKeyGroup[1] = Create_Specific_Location_Key_L(Ly_Msk, Left_M); 
	DecKeyGroup[2] = Create_Specific_Location_Key_R(Rx_Msk, Right_N,N); 
	DecKeyGroup[3] = Create_Specific_Location_Key_R(Ry_Msk, Right_M,M); 

	cout << "LX_KEY : " << DecKeyGroup[0] << endl;
	cout << "LY_KEY : " << DecKeyGroup[1] << endl;
	cout << "RX_KEY : " << DecKeyGroup[2] << endl;
	cout << "RY_KEY : " << DecKeyGroup[3] << endl;

	return DecKeyGroup;
}

Mat Decryption(Mat EncSrc, int M, int N, string* DecKeyGroup, int BlockSize, int Left_M, int Left_N, int Right_M, int Right_N) {
	Mat DecSrc = EncSrc.clone();
	string* Dec_LxKey, *Dec_LyKey, *Dec_RxKey, *Dec_RyKey;
	
	clock_t start = clock();
	Dec_LxKey = Create_EncKey_sub(Right_N-Left_N+1, DecKeyGroup[0]); 
	Dec_LyKey = Create_EncKey_sub(Right_M-Left_M+1, DecKeyGroup[1]); 
	Dec_RxKey = Create_EncKey_sub(Right_N-Left_N+1, DecKeyGroup[2]); 
	Dec_RyKey = Create_EncKey_sub(Right_M-Left_M+1, DecKeyGroup[3]); 
	clock_t end = clock();
	printf("\n........ Create Enckey : %lf  .......\n", (double)(end - start) / CLOCKS_PER_SEC);
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

string HexToASCII(string hex)
{
	int len = hex.length();
	std::string newString;
	const char* byte = hex.c_str();
	for (int i = 0; i< len; i += 2)
	{
		string byte = hex.substr(i, 2);
		char chr = (char)(int)strtol(byte.c_str(), NULL, 16);// convert hex string to ASCII
		newString += chr; 
	}
	return newString;
}


string EncKey(string lx, string ly, string rx, string ry) {
	
	std::string key = lx + ly + rx + ry;
	const char* index = "01234567";
	std::string tempKey = "";// sha256(lx + ly + rx + ry);
	for (int i = 0; i < 8; i++)	
		tempKey += sha256(key + index[i]);

	string EncKey = HexToASCII(tempKey);////HexToASCII ver 
	return EncKey; //HexToASCII ver
}

// input : image , Lx key array , Rx key array , Ly key array, Ry key array , row , column
Mat Encryption_Matrix(Mat src,string* LxKey,string* RxKey,string* LyKey,string* RyKey,int M,int N,int BlockSize) {
		for (int m = 0; m < M; m++) { 
			for (int n = 0; n < N; n++) { 
				string EncKeyData = EncKey(LxKey[n], LyKey[m], RxKey[N - n - 1], RyKey[M - m - 1]);// making the key array
				int count = 0;
				for (int i = 0; i < BlockSize; i++) {
					for (int j = 0; j < BlockSize; j++)
					{
						src.at<uchar>((BlockSize * m) + i, (BlockSize * n) + j) ^= EncKeyData[count];
						count++;
					}
				}
			}
		} 
	return src;
}

int main(int argc,char** argv)
{

	string Lx = random_string(32); 	string Ly = random_string(32);
	string Rx = random_string(32); 	string Ry = random_string(32);

	cout << "Lx : " << Lx << endl;
	cout << "Ly : " << Ly << endl;
	cout << "Rx : " << Rx << endl;
	cout << "Ry : " << Ry << endl<<endl;
	cout << "----------------------------- Init -------------------------------" << endl;

	Mat src,dst,Dec;
	int BlockSize = 16;
	int Left_N, Left_M , Right_N,Right_M;

	cout << "----------------------------- Make key array ----------------------------------" << endl << endl;;

	

	cout << "Decryption" << endl << "Decryption range - M N M* N* ( M* > M , N* > N ) \nThe example (ex. 0 0 5 6 )" << endl << endl;
	
	cin >> Left_M >> Left_N >> Right_M >> Right_N;
	
	
	// video streaming version
	

	VideoCapture cap(0); // open the default camera
	if (!cap.isOpened())  // check if we succeeded
		return -1;

	Mat test;
	cap >> test;
	int M, N;
	M = test.rows / BlockSize; 
	N = test.cols / BlockSize;

	cout << "The row of block matrix - M : " << M << endl << "The column of block matrix - N : " << N << endl;
	

	string* Lx_key = Create_EncKey(N, Lx);
	string* Ly_key = Create_EncKey(M, Ly);
	string* Rx_key = Create_EncKey(N, Rx);
	string* Ry_key = Create_EncKey(M, Ry);
	string* DecKey = CropKeyGen(M, N, Left_M, Left_N, Right_M, Right_N, Lx, Ly, Rx, Ry);


	Mat edges;
	namedWindow("edges", 1);
	Mat frame, enc, dec;
	for (;;)
	{
		
		cap >> frame; // get a new frame from camera
		
		cvtColor(frame, edges, COLOR_BGR2GRAY);
		//cvtColor(frame, edges, CV_RGB2GRAY);
		//enc = Encryption_Matrix(frame, Lx_key, Rx_key, Ly_key, Ry_key, M, N, BlockSize);// color ver , not working
		clock_t start_enc = clock();
		enc = Encryption_Matrix(edges, Lx_key, Rx_key, Ly_key, Ry_key, M, N, BlockSize);// gray ver
		clock_t end_enc = clock();
		printf("Enc time : %lf ................... ", (double)(end_enc - start_enc) / CLOCKS_PER_SEC);
		clock_t start_dec = clock();
		dec = Decryption(enc, M, N, DecKey, BlockSize, Left_M, Left_N, Right_M, Right_N);
		clock_t end_dec = clock();
		printf("Dec time : %lf\n", (double)(end_dec - start_dec) / CLOCKS_PER_SEC);
		imshow("edges", dec);
		if (waitKey(30) >= 0) break;
	}
	

	return 0;
}


