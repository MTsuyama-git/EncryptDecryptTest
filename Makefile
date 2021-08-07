.PHONY: clean encrypt decrypt

LIB_RELEASE_UTILITY	:=	Utility/bin/Release/net5.0/Utility.dll
LIB_DEBUG_UTILITY	:=	Utility/bin/Debug/net5.0/Utility.dll

ifeq ($(OS),Windows_NT)
ENCRYPT_RELEASE_TARGET	:=	Encrypt/bin/Release/net5.0/Encrypt.exe
DECRYPT_RELEASE_TARGET	:=	Decrypt/bin/Release/net5.0/Decrypt.exe
BIGNUM_RELEASE_TARGET	:=	TestBigNumber/bin/Release/net5.0/TestBigNumber.exe
ENCRYPT_DEBUG_TARGET	:=	Encrypt/bin/Debug/net5.0/Encrypt.exe
DECRYPT_DEBUG_TARGET	:=	Decrypt/bin/Debug/net5.0/Decrypt.exe
BIGNUM_DEBUG_TARGET	:=	TestBigNumber/bin/Debug/net5.0/TestBigNumber.exe
else
ENCRYPT_RELEASE_TARGET 	:=	Encrypt/bin/Release/net5.0/Encrypt
DECRYPT_RELEASE_TARGET 	:=	Decrypt/bin/Release/net5.0/Decrypt
BIGNUM_RELEASE_TARGET	:=	TestBigNumber/bin/Release/net5.0/TestBigNumber
ENCRYPT_DEBUG_TARGET 	:=	Encrypt/bin/Debug/net5.0/Encrypt
DECRYPT_DEBUG_TARGET 	:=	Decrypt/bin/Debug/net5.0/Decrypt
BIGNUM_DEBUG_TARGET	:=	TestBigNumber/bin/Debug/net5.0/TestBigNumber
endif

ENCRYPT_TARGET_NAME	:= 	Encrypt
DECRYPT_TARGET_NAME	:= 	Decrypt
BIGNUM_TARGET_NAME	:= 	TestBigNumber
LIB_TARGET_NAME		:=	Utility

UTILITY_SOURCE:= $(wildcard Utility/*.cs)

encrypt: $(ENCRYPT_RELEASE_TARGET)
	./$(ENCRYPT_RELEASE_TARGET) sample.txt sample.aes ./data_openssh/id_rsa.pub
decrypt: $(DECRYPT_RELEASE_TARGET)
	./$(DECRYPT_RELEASE_TARGET) sample.aes output.txt ./data_openssh/id_rsa
decryptrsa: $(DECRYPT_RELEASE_TARGET)
	./$(DECRYPT_RELEASE_TARGET) sample.aes sample.txt ./data_rsa/id_rsa
encryptrsa: $(ENCRYPT_RELEASE_TARGET)
	./$(ENCRYPT_RELEASE_TARGET) sample.txt sample.aes ./data_rsa/id_rsa.pub
bignum: $(BIGNUM_RELEASE_TARGET)
	./$(BIGNUM_RELEASE_TARGET)
release: $(ENCRYPT_RELEASE_TARGET)
debug: $(ENCRYPT_DEBUG_TARGET)
pem: data/id_rsa.pub
	ssh-keygen -f data/id_rsa.pub -e -m PEM > data/id_rsa.pub.pem
$(ENCRYPT_RELEASE_TARGET): Encrypt/Program.cs $(UTILITY_SOURCE)
	dotnet build -p:Configuration=Release $(ENCRYPT_TARGET_NAME)
$(ENCRYPT_DEBUG_TARGET): Encrypt/Program.cs $(UTILITY_SOURCE) 
	dotnet build -p:Configuration=Debug $(ENCRYPT_TARGET_NAME)
$(DECRYPT_RELEASE_TARGET): Decrypt/Program.cs $(UTILITY_SOURCE) 
	dotnet build -p:Configuration=Release $(DECRYPT_TARGET_NAME)
$(DECRYPT_DEBUG_TARGET): Decrypt/Program.cs $(UTILITY_SOURCE)
	dotnet build -p:Configuration=Debug $(DECRYPT_TARGET_NAME)
$(BIGNUM_RELEASE_TARGET): TestBigNumber/Program.cs $(UTILITY_SOURCE)
	dotnet build -p:Configuration=Release $(BIGNUM_TARGET_NAME)
$(BIGNUM_DEBUG_TARGET): TestBigNumber/Program.cs $(UTILITY_SOURCE)
	dotnet build -p:Configuration=Debug $(BIGNUM_TARGET_NAME)
$(LIB_RELEASE_UTILITY): $(UTILITY_SOURCE)
	dotnet build -p:Configuration=Release $(LIB_TARGET_NAME)
$(LIB_DEBUG_UTILITY):	$(UTILITY_SOURCE)
	dotnet build -p:Configuration=Debug $(LIB_TARGET_NAME)
data/id_rsa:
	@mkdir -p $(dir $@)
	ssh-keygen -f ./data/id_rsa -t rsa -m PEM
data/id_rsa_nopasswd: data/id_rsa
	cp ./data/id_rsa ./data/id_rsa_nopasswd

.PHONY: clean
clean:
	rm -rfv `find . -name bin` `find . -name obj` `find . -name *~`
