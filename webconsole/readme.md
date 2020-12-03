# free5GC Web Console

To run free5GC webconsole server. The following steps are to be considered.
```bash
# (In directory: ~/free5gc/webconsole)
cd frontend
yarn install
yarn build
rm -rf ../public
cp -R build ../public
```

### Run the Server
```bash
# (In directory: ~/free5gc/webconsole)
go run server.go
```
