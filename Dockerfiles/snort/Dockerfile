FROM public.ecr.aws/lts/ubuntu:20.04_stable
CMD ["bash"]
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get -y install git libtool pkg-config autoconf gettext libpcap-dev g++ vim make cmake wget libssl-dev liblzma-dev pip unzip protobuf-compiler golang-goprotobuf-dev
ENV GO_BIN=go1.17.2.linux-amd64.tar.gz
RUN wget https://dl.google.com/go/${GO_BIN} && tar -xvf ${GO_BIN} && mv go /usr/local && rm -rf ${GO_BIN} 
RUN export PATH=$PATH:/usr/local/go/bin 
RUN ln -s /usr/local/go/bin/go /usr/local/bin/go 
RUN go get github.com/golang/protobuf/protoc-gen-go 
RUN go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest 
RUN cp /root/go/bin/protoc-gen-go /usr/local/bin/. 
RUN cp /root/go/bin/protoc-gen-go-grpc /usr/local/bin/. 
RUN mkdir /work 
RUN mkdir /packages 
RUN cd /work && wget https://github.com/snort3/libdaq/archive/refs/tags/v3.0.5.tar.gz 
RUN cd /work && tar -xvf v3.0.5.tar.gz 
RUN cd /work/libdaq-3.0.5 && ./bootstrap && ./configure && make && make install 
RUN cd /work && rm -rf v3.0.5.tar.gz 
RUN cd /work && wget https://github.com/ofalk/libdnet/archive/refs/tags/libdnet-1.14.tar.gz 
RUN cd /work && tar -xvf libdnet-1.14.tar.gz && cd libdnet-libdnet-1.14 && ./configure && make && make install 
RUN cd /work && rm -rf libdnet-libdnet-1.14 && rm libdnet-1.14.tar.gz 
RUN cd /work && wget https://github.com/westes/flex/files/981163/flex-2.6.4.tar.gz 
RUN cd /work && tar -xvf flex-2.6.4.tar.gz && cd flex-2.6.4 && ./configure && make && make install 
RUN cd /work && rm -rf flex-2.6.4 && rm flex-2.6.4.tar.gz 
RUN cd /work && wget https://download.open-mpi.org/release/hwloc/v2.5/hwloc-2.5.0.tar.gz 
RUN cd /work && tar -xvf hwloc-2.5.0.tar.gz && cd hwloc-2.5.0 && ./configure && make && make install 
RUN cd /work && rm -rf hwloc-2.5.0 && rm hwloc-2.5.0.tar.gz 
RUN cd /work && wget https://luajit.org/download/LuaJIT-2.1.0-beta3.tar.gz 
RUN cd /work && tar -xvf LuaJIT-2.1.0-beta3.tar.gz && cd LuaJIT-2.1.0-beta3 && make && make install 
RUN cd /work && rm -rf LuaJIT-2.1.0-beta3 && rm LuaJIT-2.1.0-beta3.tar.gz 
RUN cd /work && wget https://sourceforge.net/projects/pcre/files/pcre/8.45/pcre-8.45.tar.gz 
RUN cd /work && tar -xvf pcre-8.45.tar.gz && cd pcre-8.45 && ./configure && make && make install 
RUN cd /work && rm -rf pcre-8.45 && rm pcre-8.45.tar.gz 
RUN cd /work && wget http://www.zlib.net/zlib-1.2.12.tar.gz 
RUN cd /work && tar -xvf zlib-1.2.12.tar.gz && cd zlib-1.2.12 && ./configure && make && make install 
RUN cd /work && rm -rf zlib-1.2.12 && rm zlib-1.2.12.tar.gz 
COPY daq_gwlb.zip /work/daq_gwlb.zip 
RUN cd /work && unzip daq_gwlb.zip && cd daq_gwlb-master && make && cp daq_gwlb.so /usr/local/lib/daq/. 
RUN cd /work && git clone https://github.com/snort3/snort3.git snort3_latest
RUN cd /work/snort3_latest && export my_path=/usr/local && ./configure_cmake.sh --with-daq-libraries=/usr/local/lib/daq/ --prefix=$my_path 
RUN cd /work/snort3_latest/build && make -j 6 install 
RUN tar -zcvpf /packages/libpcre.tar.gz /usr/local/lib/libpcre.so* 
RUN tar -zcvpf /packages/libluajit.tar.gz /usr/local/lib/libluajit*.so* 
RUN tar -zcvpf /packages/libhwloc.tar.gz /usr/local/lib/libhwloc.so* 
RUN tar -zcvpf /packages/libdnet.tar.gz /usr/local/lib/libdnet.so* 
RUN tar -zcvpf /packages/snort3.tar.gz /usr/local/bin/snort /usr/local/lib/daq /usr/local/etc/snort/ /usr/local/lib/libdaq.so* 
