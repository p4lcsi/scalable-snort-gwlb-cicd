FROM public.ecr.aws/lts/ubuntu:20.04_stable
CMD ["bash"]
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get -y install git libtool pkg-config autoconf gettext libpcap-dev g++ vim make cmake wget libssl-dev liblzma-dev pip unzip protobuf-compiler golang-goprotobuf-dev uuid-dev libgoogle-perftools-dev autopoint
ENV GO_BIN=go1.18.1.linux-amd64.tar.gz
RUN wget https://dl.google.com/go/${GO_BIN} && tar -xvf ${GO_BIN} && mv go /usr/local && rm -rf ${GO_BIN} 
RUN export PATH=$PATH:/usr/local/go/bin 
RUN ln -s /usr/local/go/bin/go /usr/local/bin/go 
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
RUN go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest 
RUN cp /root/go/bin/protoc-gen-go /usr/local/bin/. 
RUN cp /root/go/bin/protoc-gen-go-grpc /usr/local/bin/. 
RUN mkdir /work 
RUN mkdir /packages 
RUN cd /work && git clone https://github.com/snort3/libdaq.git libdaq
RUN cd /work/libdaq && ./bootstrap && ./configure && make && make install 
RUN cd /work && git clone https://github.com/ofalk/libdnet.git libdnet
RUN cd /work/libdnet && ./configure && make && make install
RUN apt-get -y install bison flex texinfo help2man
RUN cd /work && git clone https://github.com/westes/flex.git flex
RUN cd /work/flex && ./autogen.sh && ./configure && make && make install 
RUN cd /work && git clone https://github.com/open-mpi/hwloc.git hwloc
RUN cd /work/hwloc && ./autogen.sh && ./configure && make && make install 
RUN cd /work &&  git clone https://luajit.org/git/luajit.git luajit
RUN cd /work/luajit && make && make install 
#Snort is using the older pcre version - so we can only build from this specific version
RUN cd /work && wget https://sourceforge.net/projects/pcre/files/pcre/8.45/pcre-8.45.tar.gz
RUN cd /work && tar -xvf pcre-8.45.tar.gz && cd pcre-8.45 && ./configure && make && make install
RUN cd /work && git clone https://github.com/madler/zlib.git zlib
RUN cd /work/zlib && ./configure && make && make install 
COPY daq_gwlb.zip /work/daq_gwlb.zip 
RUN cd /work && unzip daq_gwlb.zip && cd daq_gwlb-master && make && cp daq_gwlb.so /usr/local/lib/daq/. 
RUN cd /work && git clone https://github.com/snort3/snort3.git snort3_latest
RUN export CFLAGS="-O3"
RUN export CXXFLAGS="-O3 -fno-rtti"
RUN cd /work/snort3_latest && export my_path=/usr/local && ./configure_cmake.sh --with-daq-libraries=/usr/local/lib/daq/ --prefix=$my_path --enable-tcmalloc --enable-debug  --enable-debug-msgs
RUN cd /work/snort3_latest/build && make -j$(nproc) install
