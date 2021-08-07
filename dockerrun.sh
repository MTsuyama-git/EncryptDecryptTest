docker run -it --rm --user 1000 -e DOTNET_CLI_HOME=/${HOME}/.dotnet -v /${HOME}:/${HOME} -v /${PWD}:/${PWD} -w /${PWD} dotnet:v1.0 $*
