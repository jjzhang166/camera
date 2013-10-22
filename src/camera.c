/*
 ============================================================================
 Name        : camera.c
 Author      : lsc
 Version     :
 Copyright   : R & D Center of Internet of Things Security
 Description : Hello World in C, Ansi-style
 ============================================================================
 */

#include "camera.h"

#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

char *AE_ip_addr;


int connect_to_ae()
{

    struct sockaddr_in client_addr;
    struct sockaddr_in server_addr;

    socklen_t server_addr_length;
	int client_socket;

    // 接收缓冲区
    int nRecvBuf = 32*1024; //设置为32K

    //发送缓冲区
    int nSendBuf = 32*1024; //设置为32K

    //设置一个socket地址结构client_addr,代表客户端internet地址, 端口
    bzero(&client_addr,sizeof(client_addr)); //把一段内存区的内容全部设置为0
    client_addr.sin_family = AF_INET;    //internet协议族
    client_addr.sin_addr.s_addr = INADDR_ANY;//INADDR_ANY表示自动获取本机地址
    client_addr.sin_port = htons(0);    //0表示让系统自动分配一个空闲端口
    //创建用于internet的流协议(TCP)socket,用client_socket代表客户端socket
    client_socket = socket(AF_INET,SOCK_STREAM,0);
    if( client_socket < 0)
    {
        perror("ASUE Create Socket error\n");
        return FAIL;
    }
    //把客户端的socket和客户端的socket地址结构联系起来
    if( bind(client_socket,(struct sockaddr*)&client_addr,sizeof(client_addr)))
    {
        perror("ASUE Bind Port error\n");
        return FALSE;
    }

    //设置一个socket地址结构server_addr,代表服务器的internet地址, 端口
    bzero(&server_addr,sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    if(inet_aton(AE_ip_addr,&server_addr.sin_addr) == 0) //服务器的IP地址来自程序的参数
    {
        perror("AE Server IP Address Error\n");
        return FALSE;
    }
    server_addr.sin_port = htons(CHAT_SERVER_PORT);
    server_addr_length = sizeof(server_addr);


    setsockopt(client_socket,SOL_SOCKET,SO_RCVBUF,(const BYTE *)&nRecvBuf,sizeof(int));
    setsockopt(client_socket,SOL_SOCKET,SO_SNDBUF,(const BYTE *)&nSendBuf,sizeof(int));

    //客户端向服务器发起连接,连接成功后client_socket代表了客户端和服务器的一个socket连接
    if(connect(client_socket,(struct sockaddr*)&server_addr, server_addr_length) < 0)
    {
        perror("Connect To AE error\n");
        return FALSE;
    }
    return client_socket;
}

int send_to_ae(int client_socket, BYTE *send_buffer, int send_len)
{

	int length = send(client_socket,send_buffer,send_len,0);
	//printf("--- send %d bytes ---\n",length);
	printf("---------发送 %d 字节数据！---------\n",length);
    if(length <0)
    {
        printf("Socket Send Data Failed Or Closed\n");
        close(client_socket);
        return FALSE;
    }
	else
		return TRUE;
}


int recv_from_ae(int client_socket, BYTE *recv_buffer, int recv_len)
{
	//bzero(recv_buffer, recv_len);

	int length = recv(client_socket,recv_buffer, recv_len, MSG_WAITALL);//MSG_WAITALL
	if (length < 0)
	{
		printf("Receive Data From Server Failed\n");
		return FALSE;
	}
	else if(length < recv_len)
	{
		printf("Receive data from server less than required.\n");
		return FALSE;
	}
	else if(length > recv_len)
	{
		printf("Receive data from server more than required.\n");
		return FALSE;
	}
	else
	{
		//printf("--- receive data succeed, %d bytes. ---\n",length);
		printf("---------接收数据成功, 接收 %d 字节数据！---------\n",length);
		return TRUE;
	}

}

BOOL getCertData(int userID, BYTE buf[], int *len)
{
	FILE *fp;
	char certname[40];
	memset(certname, '\0', sizeof(certname));//初始化certname,以免后面写入乱码到文件中

	if (userID == 0)
		sprintf(certname, "./cacert/cacert.pem");
	else
		sprintf(certname, "./cert/usercert%d.pem", userID);

	//printf("cert file name: %s\n", certname);

	fp = fopen(certname, "rb");
	if (fp == NULL)
	{
		printf("reading the cert file failed!\n");
		return FALSE;
	}
	*len = fread(buf, 1, 5000, fp);
	//printf("  cert's length is %d\n", *len);
	printf("数字证书的长度是 %d 字节\n", *len);
	fclose(fp);
	printf("将数字证书保存到缓存buffer成功!\n");

	return TRUE;
}

BOOL writeCertFile(int userID, BYTE buf[], int len)
{
	FILE *fp;
	char certname[40];
	memset(certname, '\0', sizeof(certname));//初始化certname,以免后面写入乱码到文件中

	if (userID == 0)
		sprintf(certname, "./cacert/cacert.pem");
	else
		//sprintf(certname, "./cert/usercert%d.pem", userID);
		sprintf(certname, "./cert/nvrreceive.pem");
	//printf("cert file name: %s\n", certname);

	fp = fopen(certname, "w");
	if (fp == NULL)
	{
		printf("open cert file failed!\n");
		return FALSE;
	}

	fwrite(buf, 1, len, fp);
	printf("数字证书长度是 %d 字节\n", len);
	fclose(fp);
	printf("完成数字证书写入操作!\n");

	return TRUE;
}
/*************************************************

Function:    // getpubkeyfromcert
Description: // 从数字证书(PEM文件)中读取公钥
Calls:       // openssl中读PEM文件的API
Called By:   // fill_certificate_auth_resp_packet
Input:	     //	用户证书的用户名certnum
Output:      //	数字证书公钥
Return:      // EVP_PKEY *pubKey
Others:      // 用户证书的用户名certnum最好是用字符串形式，但是目前是int值，有待改进

*************************************************/
EVP_PKEY *getpubkeyfromcert(int certnum)
{
	EVP_PKEY *pubKey;

	BIO * key = NULL;
	X509 * Cert = NULL; //X509证书结构体，保存CA证书
	key = BIO_new(BIO_s_file());

	char certname[60];
	memset(certname, '\0', sizeof(certname)); //初始化certname,以免后面写入乱码到文件中
	if (certnum == 0)
		sprintf(certname, "./cacert/cacert.pem");
	else
		sprintf(certname, "./cert/usercert%d.pem", certnum);

	BIO_read_filename(key,certname);
	if (!PEM_read_bio_X509(key, &Cert, 0, NULL))
	{
		/* Error 读取证书失败！*/
		printf("读取证书失败!\n");
		return NULL;
	}

	pubKey = EVP_PKEY_new();
	//获取证书公钥
	pubKey = X509_get_pubkey(Cert);
	return pubKey;
}

BOOL gen_sign(int user_ID, BYTE * input,int inputLength,BYTE * sign_value, unsigned int *sign_len,EVP_PKEY * privKey)
{
	EVP_MD_CTX mdctx;						//摘要算法上下文变量

	unsigned int temp_sign_len;
	//unsigned int i;

	//以下是计算签名代码
	EVP_MD_CTX_init(&mdctx);				//初始化摘要上下文

	if (!EVP_SignInit_ex(&mdctx, EVP_md5(), NULL))	//签名初始化，设置摘要算法，本例为MD5
	{
		printf("err\n");
		EVP_PKEY_free (privKey);
		return FALSE;
	}

	if (!EVP_SignUpdate(&mdctx, input, inputLength))	//计算签名（摘要）Update
	{
		printf("err\n");
		EVP_PKEY_free (privKey);
		return FALSE;
	}

	if (!EVP_SignFinal(&mdctx, sign_value, & temp_sign_len, privKey))	//签名输出
	{
		printf("err\n");
		EVP_PKEY_free (privKey);
		return FALSE;
	}

	*sign_len = temp_sign_len;
/*
	printf("签名值是: \n");
	for (i = 0; i < * sign_len; i++)
	{
		if (i % 16 == 0)
			printf("\n%08xH: ", i);
		printf("%02x ", sign_value[i]);
	}
	printf("\n");
*/
	EVP_MD_CTX_cleanup(&mdctx);
	return TRUE;
}

/*************************************************

Function:    // verify_sign
Description: // 验证数字签名
Calls:       // openssl验证签名的API
Called By:   // fill_certificate_auth_resp_packet
Input:	     //	input---待验证签名的整个数据包
                sign_input_len---待验证签名的有效数据字段的长度，并非整个input长度
                sign_value---签名字段
                sign_output_len---签名字段的长度
                pubKey---验证签名所使用的公钥
Output:      //	验证签名结果，TRUE or FALSE
Return:      // TRUE or FALSE
Others:      // 注意sign_input_len字段并非整个input长度，这一点今后如果感觉不合适再修改

*************************************************/

BOOL verify_sign(BYTE *input,int sign_input_len,BYTE * sign_value, unsigned int sign_output_len,EVP_PKEY * pubKey)
{
	EVP_MD_CTX mdctx;		 //摘要算法上下文变量

	EVP_MD_CTX_init(&mdctx); //初始化摘要上下文

	BYTE sign_input_buffer[10000];

	memcpy(sign_input_buffer,input,sign_input_len);    //sign_inputLength为签名算法输入长度，为所传入分组的除签名字段外的所有字段

	if (!EVP_VerifyInit_ex(&mdctx, EVP_md5(), NULL))	//验证初始化，设置摘要算法，一定要和签名一致。
	{
		printf("EVP_VerifyInit_ex err\n");
//		EVP_PKEY_free(pubKey);//pubkey只是作为参数传进来，其清理内存留给其调用者完成，这一点与参考程序不同
		return FALSE;
	}

	if (!EVP_VerifyUpdate(&mdctx, sign_input_buffer, sign_input_len))	//验证签名（摘要）Update
	{
		printf("err\n");
//		EVP_PKEY_free(pubKey);//pubkey只是作为参数传进来，其清理内存留给其调用者完成，这一点与参考程序不同
		return FALSE;
	}

	if (!EVP_VerifyFinal(&mdctx, sign_value,sign_output_len, pubKey))		//验证签名（摘要）Update
	{
		printf("EVP_Verify err\n");
//		EVP_PKEY_free(pubKey);//pubkey只是作为参数传进来，其清理内存留给其调用者完成，这一点与参考程序不同
		return FALSE;
	}
//	else
//	{
//		printf("验证签名正确!!!\n");
//	}
	//释放内存
//	EVP_PKEY_free(pubKey);//pubkey只是作为参数传进来，其清理内存留给其调用者完成，这一点与参考程序不同
	EVP_MD_CTX_cleanup(&mdctx);
	return TRUE;
}

/*************************************************

Function:    // gen_randnum
Description: // 生成随机数
Calls:       // openssl SHA256的API函数以及RAND_bytes函数
Called By:   // 待添加！！！
Input:	     //	randnum---保存生成的随机数
                randnum_len---随机数长度
Output:      //	随机数
Return:      // 256bit(32Byte)MAC
Others:      //

*************************************************/
void gen_randnum(BYTE *randnum,int randnum_len)
{
	int ret;
	BYTE randnum_seed[randnum_len];

	ret = RAND_bytes(randnum_seed, randnum_len);
	if(ret!=1)
	{
		printf("生成随机数种子失败！\n");
	}
	//参考WAPI实施指南P49 SHA-256(挑战种子)--->挑战，随机数生成算法：SHA-256(随机数种子)--->随机数
	SHA256(randnum_seed, randnum_len, randnum);
}


EVP_PKEY * getprivkeyfromprivkeyfile(int userID)
{
	EVP_PKEY * privKey;
	FILE* fp;
	//RSA rsa_struct;
	RSA* rsa;
	char keyname[40];

	if (userID == 0)
		sprintf(keyname, "./private/cakey.pem");//./demoCA/
	else
		sprintf(keyname, "./private/userkey%d.pem", userID);
	fp = fopen(keyname, "r");

	//printf("  key file name: %s\n", keyname);
	if (fp == NULL)
	{
		fprintf(stderr, "Unable to open %s for RSA priv params\n", keyname);
		return NULL;
	}

	rsa = RSA_new();
	if ((rsa = PEM_read_RSAPrivateKey(fp, &rsa, NULL, NULL)) == NULL)
	{
		fprintf(stderr, "Unable to read private key parameters\n");
		return NULL;
	}

	fclose(fp);

	// print
	//printf("Content of Private key PEM file\n");
	//RSA_print_fp(stdout, rsa, 0);
	//printf("\n");

	privKey = EVP_PKEY_new();
	if (EVP_PKEY_set1_RSA(privKey, rsa) != 1) //保存RSA结构体到EVP_PKEY结构体
	{
		printf("EVP_PKEY_set1_RSA err\n");
		RSA_free (rsa);
		return NULL;
	} else
	{
		RSA_free (rsa);
		return privKey;
	}
}


int getECDHparam(ecdh_param *ecdhparam, const char *oid)
{
	unsigned char  *buf;
	int oidlen = 0;

	oidlen=a2d_ASN1_OBJECT(NULL,0,oid,-1);
	if (oidlen <= 0)
	{
		printf("oid encode failed.\n");
		return FALSE;
	}
	buf=(unsigned char *)malloc(sizeof(unsigned char)*oidlen);
	oidlen=a2d_ASN1_OBJECT(buf,oidlen,oid,-1);

	ecdhparam->param_identify = 1;
	ecdhparam->param_length = oidlen;
	memcpy(ecdhparam->oid.oid_code, buf, oidlen);
	free(buf);

	return TRUE;
}

int getLocalIdentity(identity *localIdentity, int localUserID)
{
	BIO *b=NULL;    //bio\u63a5\u53e3
	X509 *local_cert=NULL;  //X509\u683c\u5f0f\u670d\u52a1\u7aef\u8bc1\u4e66
	X509_NAME *issuer_name=NULL;   //\u8bc1\u4e66\u9881\u53d1\u8005\u540d\u5b57
	X509_NAME *subject_name=NULL;   //\u8bc1\u4e66\u6240\u6709\u8005\u540d\u5b57
	char issuer_str[256] = {0};          //\u9881\u53d1\u8005\u540d\u5b57\u5b58\u50a8\u5b57\u7b26\u4e32
	char subject_str[256] = {0};         //\u6240\u6709\u8005\u540d\u5b57\u5b58\u50a8\u5b57\u7b26\u4e32
	long serialnum;
	int offset;
	//\u5c06PEM\u683c\u5f0f\u7684\u8bc1\u4e66\u5b58\u4e3aX509\u8bc1\u4e66\u683c\u5f0f
	char certname[40];
	memset(certname, '\0', sizeof(certname));//初始化certname,以免后面写入2乱码到文件中

	if (localUserID == 0)

		sprintf(certname, "./cacert/cacert.pem");
	else

		sprintf(certname, "./cert/usercert%d.pem", localUserID);

	//printf("cert file name: %s\n", certname);

	SSLeay_add_all_algorithms();   //\u52a0\u8f7d\u76f8\u5173\u7b97\u6cd5
	b=BIO_new_file(certname,"r");
	local_cert=PEM_read_bio_X509(b,NULL,NULL,NULL);
	BIO_free(b);
	if(local_cert==NULL)
	{
		printf("open local cert failed.\n");
		X509_free(local_cert);
		return FALSE;
	}

	issuer_name=X509_get_issuer_name(local_cert);
	X509_NAME_oneline(issuer_name,issuer_str,256);

	subject_name=X509_get_subject_name(local_cert);
	X509_NAME_oneline(subject_name,subject_str,256);

	serialnum = ASN1_INTEGER_get(X509_get_serialNumber(local_cert));
	X509_free(local_cert);

	localIdentity->identity_identify = 1; //X.509 cert

	offset = 0;
	memcpy(localIdentity->cer_der.data + offset, (BYTE*)subject_str, strlen(subject_str));
	offset += strlen(subject_str);
	memcpy(localIdentity->cer_der.data + offset, (BYTE*)issuer_str, strlen(issuer_str));
	offset += strlen(issuer_str);
	memcpy(localIdentity->cer_der.data + offset, (BYTE*)&serialnum, sizeof(serialnum)/sizeof(BYTE));
	offset += sizeof(serialnum);

	localIdentity->identity_length = offset;

	return TRUE;

}


int HandleWAPIProtocolAuthActive(int user_ID, auth_active *auth_active_packet)
{
	//write ae cert into cert file
	//printf("write ae cert into cert file:\n");
	int ae_ID = 2;
	//writeCertFile(ae_ID, (BYTE *)auth_active_packet->certificatestaae.cer_X509, (int)auth_active_packet->certificatestaae.cer_length);

	//verify sign of AE
	//printf("verify sign of AE:\n");
	//read ae certificate get ae pubkey(公钥)
	EVP_PKEY *aepubKey = NULL;
	BYTE *pTmp = NULL;
	BYTE deraepubkey[1024];
	int aepubkeyLen;
	aepubKey = getpubkeyfromcert(ae_ID);
	if(aepubKey == NULL)
	{
		printf("get ae's public key failed.\n");
		return FALSE;
	}
	pTmp = deraepubkey;
	//把证书公钥转换为DER编码的数据，以方便打印(aepubkey结构体不方便打印)
	aepubkeyLen = i2d_PublicKey(aepubKey, &pTmp);

	//verify the sign
	if (verify_sign((BYTE *) auth_active_packet,
			sizeof(auth_active) - sizeof(sign_attribute),
			auth_active_packet->aesign.sign.data,
			auth_active_packet->aesign.sign.length, aepubKey))
	{
		printf("验证网络硬盘录像机的签名正确!!!\n");
		EVP_PKEY_free(aepubKey);
	}else
	{
		printf("ae's sign verify failed.\n");
		return FALSE;
	}

	//verify FLAG
	//printf("verify FLAG:\n");
	if(auth_active_packet->flag != 0x00)
	{
		printf("Not the first time access.\n");
		return FALSE;
	}

	//verify auth identity, is same as before
	//first time skip this step
	//printf("verify auth identity.\n");

	return TRUE;
}


//2) ProcessWAPIProtocolAccessAuthRequest
int fill_access_auth_requ_packet(int user_ID,auth_active *auth_active_packet, access_auth_requ *access_auth_requ_packet)
{
	//fill WAI packet head
	//printf("fill WAI packet head:\n");
	access_auth_requ_packet->wai_packet_head.version = 1;
	access_auth_requ_packet->wai_packet_head.type = 1;
	access_auth_requ_packet->wai_packet_head.subtype = AUTH_ACTIVE;
	access_auth_requ_packet->wai_packet_head.reserved = 0;
	access_auth_requ_packet->wai_packet_head.packetnumber = 1;
	access_auth_requ_packet->wai_packet_head.fragmentnumber = 0;
	access_auth_requ_packet->wai_packet_head.identify = 0;

	//fill flag
	//printf("fill flag:\n");
	access_auth_requ_packet->flag = 0x04;

	//fill auth identify, same as auth active packet
	//printf("fill auth identify:\n");
	memcpy((BYTE *)&access_auth_requ_packet->authidentify, (BYTE *)&auth_active_packet->authidentify, sizeof(access_auth_requ_packet->authidentify));

	//fill asue rand number
	//printf("fill asue rand number:\n");
	gen_randnum((BYTE *)&access_auth_requ_packet->asuechallenge, sizeof(access_auth_requ_packet->aechallenge));

	//fill asue cipher data
	//printf("fill asue cipher data, unfinished!!!\n");
	memset((BYTE *)&access_auth_requ_packet->asuekeydata, 0, sizeof(access_auth_requ_packet->asuekeydata));

	//fill ae rand number, same as auth active packet
	//printf("fill ae rand number:\n");
	memcpy((BYTE *)&access_auth_requ_packet->aechallenge, (BYTE *)&auth_active_packet->aechallenge, sizeof(access_auth_requ_packet->aechallenge));

	//fill ae identity
	//printf("fill ae identity:\n");
	int ae_ID = 2;
	getLocalIdentity(&access_auth_requ_packet->staaeidentity, ae_ID);

	//fill ecdh param, same as auth active packet
	//printf("fill ecdh param:\n");
	const  char  oid[]={"1.2.156.11235.1.1.2.1"};
	getECDHparam(&access_auth_requ_packet->ecdhparam, oid);

	//fill asue certificate
	//printf("fill asue certificate:\n");
	access_auth_requ_packet->certificatestaasue.cer_identify = 1; //X.509 cert

	BYTE cert_buffer[5000];
	int cert_len = 0;

	if (!getCertData(user_ID, cert_buffer, &cert_len))	  //先读取ASUE证书，"./cert/usercert1.pem"
	{
		printf("将证书保存到缓存buffer失败!");
		return FALSE;
	}

	access_auth_requ_packet->certificatestaasue.cer_length = cert_len;   //证书长度字段
	memcpy((access_auth_requ_packet->certificatestaasue.cer_X509),(BYTE*)cert_buffer,strlen((char*)cert_buffer));


	//fill packet length
	access_auth_requ_packet->wai_packet_head.length = sizeof(access_auth_requ);


	//fill asue signature
	//printf("fill asue signature:\n");
	//AE\u4f7f\u7528AE\u7684\u79c1\u94a5(userkey2.pem)\u6765\u751f\u6210AE\u7b7e\u540d
	EVP_PKEY * privKey;
	BYTE sign_value[1024];					//保存签名值的数组
	unsigned int  sign_len;

	privKey = getprivkeyfromprivkeyfile(user_ID);
	if(privKey == NULL)
	{
		printf("getprivkeyitsself().....failed!\n");
		return FALSE;
	}

	if(!gen_sign(user_ID, (BYTE *)access_auth_requ_packet,(access_auth_requ_packet->wai_packet_head.length-sizeof(access_auth_requ_packet->asuesign)),sign_value, &sign_len,privKey))
	{
		printf("generate signature failed.\n");
		return FALSE;
	}

	access_auth_requ_packet->asuesign.sign.length = sign_len;
	memcpy(access_auth_requ_packet->asuesign.sign.data,sign_value,sign_len);

	return TRUE;

}

int ProcessWAPIProtocolAccessAuthRequest(int user_ID,auth_active *auth_active_packet, access_auth_requ *access_auth_requ_packet)
{
	memset((BYTE *)access_auth_requ_packet, 0, sizeof(access_auth_requ));
	if (!fill_access_auth_requ_packet(user_ID,auth_active_packet, access_auth_requ_packet))
	{
		printf("fill access auth request packet failed!\n");
		exit(0);
	}
	else
		printf("摄像机封装【接入认证请求分组】成功！准备发往网络硬盘录像机！\n");

	return TRUE;
}


//3)
//int ProcessWAPIProtocolCertAuthRequest()

//4)
//int ProcessWAPIProtocolCertAuthResp()


//5)
//int ProcessWAPIProtocolAccessAuthResp()

int HandleWAPIProtocolAccessAuthResp(int user_ID, access_auth_requ *access_auth_requ_packet,access_auth_resp *access_auth_resp_packet)
{
	//verify sign of AE
	//printf("verify sign of AE:\n");
	//read ae certificate get ae pubkey(公钥)
	EVP_PKEY *aepubKey = NULL;
	BYTE *pTmp = NULL;
	BYTE deraepubkey[1024];
	int aepubkeyLen;
	int ae_ID = 2;
	aepubKey = getpubkeyfromcert(ae_ID);
	if(aepubKey == NULL){
		printf("get ae's public key failed.\n");
		return FALSE;
		}

	pTmp = deraepubkey;
	//把证书公钥转换为DER编码的数据，以方便打印(aepubkey结构体不方便打印)
	aepubkeyLen = i2d_PublicKey(aepubKey, &pTmp);

	//verify the sign
	if (verify_sign((BYTE *) access_auth_resp_packet,
			sizeof(access_auth_resp) - sizeof(sign_attribute),
			access_auth_resp_packet->aesign.sign.data,
			access_auth_resp_packet->aesign.sign.length, aepubKey))
	{
		printf("验证网络硬盘录像机的签名正确!!!\n");
		EVP_PKEY_free(aepubKey);
	}else
	{
		printf("ae's sign verify failed.\n");
		return FALSE;
	}

	//verify access result
	if(access_auth_resp_packet->accessresult != 0)
	{
		printf("verity access result failed.\n");
		return FALSE;
	}
	else
		printf("接入认证结果为成功!!!\n");

	//verify FLAG
//	printf("verify FLAG:\n");
//	if(access_auth_resp_packet->flag != 0x04)
//	{
//		printf("verity flag failed.\n");
//		return FALSE;
//	}

	//verify auth identity is same as access auth requ packet
	//printf("verify auth identity:\n");
	if(memcmp(access_auth_resp_packet->authidentify,
		access_auth_requ_packet->authidentify,
		sizeof(access_auth_resp_packet->authidentify)) != 0)
	{
		printf("verify auth identity failed!\n");
		return FALSE;
	}

	//verify ASUE AE random number
	//printf("verify ASUE, AE rand number:\n");
	if(memcmp(access_auth_resp_packet->asuechallenge,
		access_auth_requ_packet->asuechallenge,
		sizeof(access_auth_resp_packet->asuechallenge)) != 0)
	{
		printf("verify ASUE random number failed!\n");
		return FALSE;
	}

	if(memcmp(access_auth_resp_packet->aechallenge,
		access_auth_requ_packet->aechallenge,
		sizeof(access_auth_resp_packet->aechallenge)) != 0)
	{
		printf("verify AE random number failed!\n");
		return FALSE;
	}

	//verify cert valid result: verify sign of ASU
	//printf("verify cert valid result: verify sign of ASU:\n");
	//read ae certificate get ae pubkey(公钥)
	EVP_PKEY *asupubKey = NULL;
	//BYTE *pTmp = NULL;
	BYTE derasupubkey[1024];
	int asupubkeyLen;
	int asu_ID = 0;
	asupubKey = getpubkeyfromcert(asu_ID);

	pTmp = derasupubkey;
	//把证书公钥转换为DER编码的数据，以方便打印(aepubkey结构体不方便打印)
	asupubkeyLen = i2d_PublicKey(asupubKey, &pTmp);

	//verify the sign
	if (verify_sign((BYTE *)&access_auth_resp_packet->cervalrescomplex,
			sizeof(access_auth_resp_packet->cervalrescomplex) - sizeof(sign_attribute),
			access_auth_resp_packet->cervalrescomplex.ae_asue_cert_valid_result_asu_sign.sign.data,
			access_auth_resp_packet->cervalrescomplex.ae_asue_cert_valid_result_asu_sign.sign.length,
			asupubKey))
	{
		printf("验证认证服务器签名正确!!!\n");
		EVP_PKEY_free(asupubKey);
	}
	else
	{
		printf("asu's sign verify failed.\n");
		return FALSE;
	}

	//verify cert valid result of AE
	//printf("verify cert valid result of AE:\n");
	printf("网络硬盘录像机数字证书验证结果:");
	if(access_auth_resp_packet->cervalrescomplex.ae_asue_cert_valid_result.cerresult2 != 0)
	{
		printf("verify cert valid result failed.\n");
		return FALSE;
	}
	else
		printf("网络硬盘录像机数字证书验证成功!!!\n");
	//printf("Authentication succeed!!\n");
	return TRUE;
}

void ProcessWAPIProtocol(int new_ae_socket)
{
	int user_ID = 1;
	auth_active auth_active_packet;
	access_auth_requ access_auth_requ_packet;
	access_auth_resp access_auth_resp_packet;

	//printf("\n***\n Connect to ae.\n");

	printf("\n*********\n 摄像机连接网络硬盘录像机.\n");
	//1) ProcessWAPIProtocolAuthActive
	printf("\n*********\n 1) 摄像机接收、解析网络硬盘录像机发来的【认证激活分组】: \n");

	memset((BYTE *)&auth_active_packet, 0, sizeof(auth_active));
	//printf("recv auth active packet from AE...\n");
	recv_from_ae(new_ae_socket, (BYTE *)&auth_active_packet, sizeof(auth_active_packet));

	HandleWAPIProtocolAuthActive(user_ID, &auth_active_packet);

	//2) ProcessWAPIProtocolAccessAuthRequest
	printf("\n*********\n 2) 摄像机封装【接入认证请求分组】: \n");
	//stop for keyboard
	getchar();
	ProcessWAPIProtocolAccessAuthRequest(user_ID,&auth_active_packet, &access_auth_requ_packet);

	//printf("send to ae...\n");
	printf("摄像机发送【接入认证请求分组】给网络硬盘录像机\n");
	send_to_ae(new_ae_socket, (BYTE *)&access_auth_requ_packet, sizeof(access_auth_requ_packet));

	//3) ProcessWAPIProtocolCertAuthRequest
	//printf("3) ProcessWAPIProtocolCertAuthRequest: \n");
	//4) ProcessWAPIProtocolCertAuthResp
	//printf("4) ProcessWAPIProtocolCertAuthResp: \n");

	//5) ProcessWAPIProtocolAccessAuthResp
	printf("\n*********\n 5) 摄像机接收、解析网络硬盘录像机发来的【接入认证响应分组】: \n");

	memset((BYTE *)&access_auth_resp_packet, 0, sizeof(access_auth_resp));
	//printf("recv from ae...\n");
	recv_from_ae(new_ae_socket, (BYTE *)&access_auth_resp_packet, sizeof(access_auth_resp_packet));

	if(HandleWAPIProtocolAccessAuthResp(user_ID, &access_auth_requ_packet, &access_auth_resp_packet) == FALSE)
	{
		printf("Authentication failed!!\n");
		exit(1);
	}
	else
	{
		exit(0);
	}
}

int main(int argc, char **argv)
{

	int new_ae_socket;

	OpenSSL_add_all_algorithms();

	if (argc != 2)
	{
		printf("Usage: ./%s AE_ip_address\n", argv[0]);
		exit(1);
	}

	AE_ip_addr = argv[1];

	new_ae_socket = connect_to_ae();

	ProcessWAPIProtocol(new_ae_socket);

	return 0;
}
