
```
export SRC=${HOME}/warden
export BASE=${HOME}/warden-config
mkdir -p ${BASE}/etc ${BASE}/signers ${BASE}/certs
cp ${SRC}/etc/android-ota-sample.json ${BASE}/etc/warden.json
gvim ${BASE}/etc/warden.json
cd ${BASE}/etc
GOPATH=${SRC} go run ${SRC}/src/main/mkservercert.go
# openssl the various certs
cd ${SRC}
GOPATH=${SRC} go run src/main/warden.go -config ${BASE}/etc/warden.json
```
