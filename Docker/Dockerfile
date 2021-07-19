from alpine:3.13
ARG DOTNET_INSTALL_DEST=/usr/local/bin
RUN apk add bash curl icu-libs krb5-libs libgcc libintl libssl1.1 libstdc++ zlib &&\
    curl -L https://dot.net/v1/dotnet-install.sh | bash -s -- -c 5.0 --install-dir $DOTNET_INSTALL_DEST
ARG dotnet_cli_home_arg=/tmp/
ENV DOTNET_CLI_HOME=$dotnet_cli_home_arg
ENV DOTNET_ROOT=$DOTNET_INSTALL_DEST
