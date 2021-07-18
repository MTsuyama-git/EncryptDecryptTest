data/id_rsa:
	@mkdir -p $(dir $@)
	ssh-keygen -f ./data/id_rsa -t rsa -m PEM
