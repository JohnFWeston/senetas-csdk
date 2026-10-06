#!/bin/bash
#set -x
CHOICE=${1:-"aes"}

export BASE_DIR=${PWD}/..
export LD_LIBRARY_PATH=$BASE_DIR/openssl-1.1.1n
export OPENSSL_ENGINES=$BASE_DIR/libcsdk/build/lib/

RESULTS="./.results"

OPSS=()
RATE=()
PCNT=()
PCNTK=()

store_results()
{
echo "."
while read -r line; do
   IFS=':' read -r -a item <<< $line
   #echo "item is ${item[0]}"
   if [[ "${item[0]}" == "+R" ]]; then
      OPS=${item[1]}
   fi
   if [[ "${item[0]}" == "+F" ]]; then
      DAT=${item[3]}
   fi
done < "$RESULTS"
OPSS+=("$OPS")
RATE+=("$DAT")
}

if [[ "$CHOICE" == "chacha20_poly1305" ]]; then

echo "EXECUTING selftest for baseline CHACHA20_POLY1305"
{
$BASE_DIR/openssl-1.1.1n/apps/openssl speed -evp chacha20-poly1305 -bytes 1024 -seconds 1 -mr
} 1>$RESULTS 2>&1
store_results
echo "EXECUTING selftest for engine"
{
$BASE_DIR/openssl-1.1.1n/apps/openssl speed -evp chacha20-poly1305 -bytes 1024 -seconds 1 -mr -engine libcsdk
} 1>$RESULTS 2>&1
store_results

#echo ${OPSS[@]}
#echo ${RATE[@]}
PCNT+=(`echo "scale=2; 100* ( ${OPSS[1]}/${OPSS[0]} )" | bc`)

PCNTK+=(`echo "scale=2; 100* ( ${RATE[1]}/${RATE[0]} )" | bc`)

printf "CSDK comparison   | %20s | %20s | %.20s\n" "CHACHA calc/s" "Engine calc/s" "% change"
printf "          256-aead| %20s | %20s | %.2f\n" "${OPSS[0]}" "${OPSS[1]}" "${PCNT[0]}"

printf "CSDK comparison   | %20s | %20s | %.20s\n" "CHACHA k/s" "Engine k/s" "% change"
printf "          256-aead| %20s | %20s | %.2f\n" "${RATE[0]}" "${RATE[1]}" "${PCNTK[0]}"

else

echo "EXECUTING selftest for baseline AESNI"
{
#$BASE_DIR/openssl-1.1.1n/apps/openssl speed -evp camellia-256-cfb -bytes 1024 -seconds 1 -mr
$BASE_DIR/openssl-1.1.1n/apps/openssl speed -evp aes-256-cfb -bytes 1024 -seconds 1 -mr
} 1>$RESULTS 2>&1
store_results
{
$BASE_DIR/openssl-1.1.1n/apps/openssl speed -evp aes-256-ctr -bytes 1024 -seconds 1 -mr
} 1>$RESULTS 2>&1
store_results
{
$BASE_DIR/openssl-1.1.1n/apps/openssl speed -evp aes-256-gcm -bytes 1024 -seconds 1 -mr
} 1>$RESULTS 2>&1
store_results

echo "EXECUTING selftest for engine"
{
$BASE_DIR/openssl-1.1.1n/apps/openssl speed -evp aes-256-cfb -bytes 1024 -seconds 1 -mr -engine libcsdk
} 1>$RESULTS 2>&1
store_results
{
$BASE_DIR/openssl-1.1.1n/apps/openssl speed -evp aes-256-ctr -bytes 1024 -seconds 1 -mr -engine libcsdk
} 1>$RESULTS 2>&1
store_results
{
$BASE_DIR/openssl-1.1.1n/apps/openssl speed -evp aes-256-gcm -bytes 1024 -seconds 1 -mr -engine libcsdk
} 1>$RESULTS 2>&1
store_results

#echo ${OPSS[@]}
#echo ${RATE[@]}
PCNT+=(`echo "scale=2; 100* ( ${OPSS[3]}/${OPSS[0]} )" | bc`)
PCNT+=(`echo "scale=2; 100* ( ${OPSS[4]}/${OPSS[1]} )" | bc`)
PCNT+=(`echo "scale=2; 100* ( ${OPSS[5]}/${OPSS[2]} )" | bc`)

PCNTK+=(`echo "scale=2; 100* ( ${RATE[3]}/${RATE[0]} )" | bc`)
PCNTK+=(`echo "scale=2; 100* ( ${RATE[4]}/${RATE[1]} )" | bc`)
PCNTK+=(`echo "scale=2; 100* ( ${RATE[5]}/${RATE[2]} )" | bc`)

printf "CSDK comparison   | %20s | %20s | %.20s\n" "AESNI calc/s" "Engine calc/s" "% change"
printf "          256-cfb | %20s | %20s | %.2f\n" "${OPSS[0]}" "${OPSS[3]}" "${PCNT[0]}"
printf "          256-ctr | %20s | %20s | %.2f\n" "${OPSS[1]}" "${OPSS[4]}" "${PCNT[1]}"
printf "          256-gcm | %20s | %20s | %.2f\n" "${OPSS[2]}" "${OPSS[5]}" "${PCNT[2]}"

printf "CSDK comparison   | %20s | %20s | %.20s\n" "AESNI k/s" "Engine k/s" "% change"
printf "          256-cfb | %20s | %20s | %.2f\n" "${RATE[0]}" "${RATE[3]}" "${PCNTK[0]}"
printf "          256-ctr | %20s | %20s | %.2f\n" "${RATE[1]}" "${RATE[4]}" "${PCNTK[1]}"
printf "          256-gcm | %20s | %20s | %.2f\n" "${RATE[2]}" "${RATE[5]}" "${PCNTK[2]}"

fi
