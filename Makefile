.PHONY: clean encrypt decrypt

encrypt: Encrypt/bin/Release/net5.0
	./Encrypt/bin/Release/net5.0/Encrypt sample.txt sample.aes ./data.pub.txt
decrypt: Decrypt/bin/Release/net5.0
	./Decrypt/bin/Release/net5.0/Decrypt sample.txt sample.aes ./data_nopasswd.txt
release: Encrypt/bin/Release/net5.0
debug: Encrypt/bin/Debug/net5.0
Encrypt/bin/Release/net5.0: 
	dotnet build -p:Configuration=Release -p:Platform="Any CPU"
Encrypt/bin/Debug/net5.0:
	dotnet build -p:Configuration=Debug -p:Platform="Any CPU"
data/id_rsa:
	@mkdir -p $(dir $@)
	ssh-keygen -f ./data/id_rsa -t rsa -m PEM

.PHONY: clean
clean:
	rm -rfv `find -name bin` `find -name obj` `find -name *~`
