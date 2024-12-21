#!/bin/bash
set -e

# Initialize variables
assetName=""
token=""
apiUrl=""

supplyChainId=$RANDOM

echo "Supply Chain ID: $supplyChainId"

# Loop through the arguments
for arg in "$@"; do
    case $arg in
        --assetName=*)
            assetName="${arg#*=}"  # Extract value after '='
            ;;
        --token=*)
            token="${arg#*=}"
            ;;
        --apiUrl=*)
            apiUrl="${arg#*=}"
            ;;
        *)
            echo "Unknown argument: $arg"
            ;;
    esac
done

# first create a new directory as "Project"
mkdir test-supply-chain

# create a new file called
echo "Test the supply chain" > test-supply-chain/README.md

# execute the first step
go run ./cmd/devguard-scanner/main.go intoto run --step=post-commit --products=test-supply-chain/README.md --token=$token --apiUrl=$apiUrl --assetName=$assetName --supplyChainId=$supplyChainId

# lets do the build step
go run ./cmd/devguard-scanner/main.go intoto start --step=build --materials=test-supply-chain/README.md --token=$token --apiUrl=$apiUrl --assetName=$assetName --supplyChainId=$supplyChainId

# just zip the README.md
zip test-supply-chain/test-supply-chain.zip test-supply-chain/README.md

go run ./cmd/devguard-scanner/main.go intoto stop --step=build --products=test-supply-chain/test-supply-chain.zip --token=$token --apiUrl=$apiUrl --assetName=$assetName --supplyChainId=$supplyChainId

# great - now lets do the deploy step.
# we need to create an image digest as txt
echo "sha256:$(shasum -a 256 test-supply-chain/test-supply-chain.zip | awk '{print $1}')" > image-digest.txt

go run ./cmd/devguard-scanner/main.go intoto run --step=deploy --materials=test-supply-chain/test-supply-chain.zip --products=image-digest.txt  --token=$token --apiUrl=$apiUrl --assetName=$assetName --supplyChainId=$supplyChainId --supplyChainOutputDigest=$(cat image-digest.txt)

rm -rf test-supply-chain
rm image-digest.txt