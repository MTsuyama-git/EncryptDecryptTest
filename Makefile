.PHONY: clean encrypt decrypt

DOTNET_CLI_HOME := $(HOME)/.dotnet

ifeq ($(ENV),docker)
DOCKER_CMD  :=  docker run --rm --user 1000 -e DOTNET_CLI_HOME=$(DOTNET_CLI_HOME) -v $(HOME):$(HOME) -v $(PWD):$(PWD) -w $(PWD) dotnet:v1.0
endif

LIB_RELEASE_UTILITY	:=	Utility/bin/Release/net5.0/Utility.dll
LIB_DEBUG_UTILITY	:=	Utility/bin/Debug/net5.0/Utility.dll

ifeq ($(OS),Windows_NT)
ENCRYPT_RELEASE_TARGET	:=	Encrypt/bin/Release/net5.0/Encrypt.exe
DECRYPT_RELEASE_TARGET	:=	Decrypt/bin/Release/net5.0/Decrypt.exe
ENCRYPT_DEBUG_TARGET	:=	Encrypt/bin/Debug/net5.0/Encrypt.exe
DECRYPT_DEBUG_TARGET	:=	Decrypt/bin/Debug/net5.0/Decrypt.exe
else
ENCRYPT_RELEASE_TARGET 	:= Encrypt/bin/Release/net5.0/Encrypt
DECRYPT_RELEASE_TARGET 	:= Decrypt/bin/Release/net5.0/Decrypt
ENCRYPT_DEBUG_TARGET := Encrypt/bin/Debug/net5.0/Encrypt
DECRYPT_DEBUG_TARGET := Decrypt/bin/Debug/net5.0/Decrypt
endif

UTILITY_SOURCE:= $(wildcard Utility/*.cs)

encrypt: $(ENCRYPT_RELEASE_TARGET)
	$(DOCKER_CMD) ./$(ENCRYPT_RELEASE_TARGET) sample.txt sample.aes ./data_openssh/id_rsa.pub
decrypt: $(DECRYPT_RELEASE_TARGET)
	$(DOCKER_CMD) ./$(DECRYPT_RELEASE_TARGET) sample.txt sample.aes ./data_openssh/id_rsa
release: $(ENCRYPT_RELEASE_TARGET)
debug: $(ENCRYPT_DEBUG_TARGET)
pem: data/id_rsa.pub
	ssh-keygen -f data/id_rsa.pub -e -m PEM > data/id_rsa.pub.pem
$(ENCRYPT_RELEASE_TARGET): Encrypt/Program.cs $(UTILITY_SOURCE)
	$(DOCKER_CMD) dotnet build -p:Configuration=Release -p:Platform="Any CPU"
$(ENCRYPT_DEBUG_TARGET): Encrypt/Program.cs $(UTILITY_SOURCE)
	$(DOCKER_CMD) dotnet build -p:Configuration=Debug -p:Platform="Any CPU"
$(DECRYPT_RELEASE_TARGET): Decrypt/Program.cs $(UTILITY_SOURCE)
	$(DOCKER_CMD) dotnet build -p:Configuration=Release -p:Platform="Any CPU"
$(DECRYPT_DEBUG_TARGET): Decrypt/Program.cs $(UTILITY_SOURCE)
	$(DOCKER_CMD) dotnet build -p:Configuration=Debug -p:Platform="Any CPU"
$(LIB_RELEASE_UTILITY): $(UTILITY_SOURCE)
	$(DOCKER_CMD) dotnet build -p:Configuration=Release -p:Platform="Any CPU"
$(LIB_DEBUG_UTILITY):	$(UTILITY_SOURCE)
	$(DOCKER_CMD) dotnet build -p:Configuration=Debug -p:Platform="Any CPU"
data/id_rsa:
	@mkdir -p $(dir $@)
	ssh-keygen -f ./data/id_rsa -t rsa -m PEM
data/id_rsa_nopasswd: data/id_rsa
	cp ./data/id_rsa ./data/id_rsa_nopasswd

.PHONY: clean
clean:
	rm -rfv `find . -name bin` `find . -name obj` `find . -name *~`
