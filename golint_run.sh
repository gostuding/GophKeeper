echo "Run golangci"
$(go env GOPATH)/bin/golangci-lint run -c $PWD/.golangci.yml > ./golangci-lint/report-unformatted.json
cd ./golangci-lint
echo "Convert"
python3 ./recomp.py
rm ./report-unformatted.json
echo "Done"
