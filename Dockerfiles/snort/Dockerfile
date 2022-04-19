FROM public.ecr.aws/amazonlinux/amazonlinux:latest
CMD ["bash"]
RUN yum update && yum -y install git libtool pkg-config autoconf gettext-devel libpcap-devel gcc-c++ vim make cmake wget openssl-devel liblzma-devel pip unzip protobuf-compiler golang-goprotobuf-devel uuid-devel libgoogle-perftools-devel bison flex texinfo help2man
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
RUN cd /work && wget https://github.com/westes/flex/files/981163/flex-2.6.4.tar.gz 
RUN cd /work && tar -xvf flex-2.6.4.tar.gz && cd flex-2.6.4 && ./configure && make && make install 
RUN cd /work && rm -rf flex-2.6.4 && rm flex-2.6.4.tar.gz 
RUN cd /work && wget https://download.open-mpi.org/release/hwloc/v2.5/hwloc-2.5.0.tar.gz 
RUN cd /work && tar -xvf hwloc-2.5.0.tar.gz && cd hwloc-2.5.0 && ./configure && make && make install 
RUN cd /work && rm -rf hwloc-2.5.0 && rm hwloc-2.5.0.tar.gz 
RUN cd /work && wget https://luajit.org/download/LuaJIT-2.1.0-beta3.tar.gz 
RUN cd /work && tar -xvf LuaJIT-2.1.0-beta3.tar.gz && cd LuaJIT-2.1.0-beta3 && make && make install 
RUN cd /work && rm -rf LuaJIT-2.1.0-beta3 && rm LuaJIT-2.1.0-beta3.tar.gz 
#Snort is using the older pcre version - so we can only build from this specific version
RUN cd /work && wget https://sourceforge.net/projects/pcre/files/pcre/8.45/pcre-8.45.tar.gz
RUN cd /work && tar -xvf pcre-8.45.tar.gz && cd pcre-8.45 && ./configure && make && make install
RUN cd /work && rm -rf pcre-8.45 && rm pcre-8.45.tar.gz
RUN cd /work && wget http://www.zlib.net/zlib-1.2.12.tar.gz 
RUN cd /work && tar -xvf zlib-1.2.12.tar.gz && cd zlib-1.2.12 && ./configure && make && make install 
RUN cd /work && rm -rf zlib-1.2.12 && rm zlib-1.2.12.tar.gz 
COPY daq_gwlb.zip /work/daq_gwlb.zip 
RUN cd /work && unzip daq_gwlb.zip && cd daq_gwlb-master && make && cp daq_gwlb.so /usr/local/lib/daq/. 
#Workaround for cmake - correct cmake to cmake3 at the beginning
RUN yum -y install cmake3
RUN yum -y remove cmake
RUN ln -s /usr/bin/cmake3 /usr/bin/cmake
#Add these two lines at the beginning
RUN amazon-linux-extras install epel -y
RUN yum -y install luajit-devel gperftools-devel hwloc-devel
RUN cd /work && git clone https://github.com/snort3/snort3.git snort3_latest
RUN export CFLAGS="-O3"
RUN export CXXFLAGS="-O3 -fno-rtti"
RUN cd /work/snort3_latest && export my_path=/usr/local && ./configure_cmake.sh --with-daq-libraries=/usr/local/lib/daq/ --prefix=$my_path --enable-tcmalloc --enable-debug  --enable-debug-msgs
RUN cd /work/snort3_latest/build && make -j$(nproc) install
#RUN mkdir /var/log/snort

#COPY Docker Entrypoint + snot config + maybe the pulled pork

#groupadd snort
#useradd snort -r -M -g snort -s /sbin/nologin -c SNORT_SERVICE_ACCOUNT

# mkdir /var/log/snort
# chmod -R 5700 /var/log/snort
# chown -R snort:snort /var/log/snort