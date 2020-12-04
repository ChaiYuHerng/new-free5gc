#!/usr/bin/env bash

NF_LIST="amf ausf nrf nssf pcf smf udm udr"

for NF in ${NF_LIST}; do 
    echo "Start build ${NF}...."
    go build -o bin/${NF} -x src/${NF}/${NF}.go
done


