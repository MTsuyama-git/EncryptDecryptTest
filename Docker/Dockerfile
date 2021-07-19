from ubuntu:20.04
ARG runner_name=runner
ARG runner_home=/home/${runner_name}
ARG runner_uid=1000
ARG runner_gid=1000
ENV DEBIAN_FRONTEND=noninsteractive
RUN addgroup --gid ${runner_gid} ${runner_name} &&\
    useradd --no-create-home --uid ${runner_uid} --gid ${runner_gid} ${runner_name} &&\
    gpasswd -a ${runner_name} sudo &&\
    apt -y update && \
    apt -y install build-essential vim wget kmod libxml2 git sudo && \
    # apt -y install --no-install-recommends -o DPkg::options::="--force-confdef" -o DPkg::options::="--force-confold" make build-essential libssl-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev wget curl llvm libncurses5-dev xz-utils tk-dev libxml2-dev libxmlsec1-dev libffi-dev liblzma-dev &&\
    mkdir ${runner_home} &&\
    chown ${runner_uid}:${runner_gid} ${runner_home} &&\
    passwd --expire ${runner_name} &&\
    echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers
#    sh ./cuda_10.1.105_418.39_linux.run 
USER ${runner_name}
RUN  echo "shopt -s autocd" >> ${runner_home}/.bashrc &&\ 
     wget -O ${runner_home}/packages-microsoft-prod.deb https://packages.microsoft.com/config/ubuntu/20.04/packages-microsoft-prod.deb &&\
     sudo dpkg -i ${runner_home}/packages-microsoft-prod.deb &&\
     sudo apt update &&\
     sudo apt install -y apt-transport-https &&\
     sudo apt update &&\
     sudo apt install -y dotnet-sdk-5.0
VOLUME ${runner_home}/workspace
