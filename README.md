# Haproxy configured via a cli with automatic SSL (Let's encrypt)

## Run the example

```bash
cd examples
docker-compose build
docker-compose up
```

## Build the binary

```bash
make install
```

## Add a frontend

```bash
haproxy-letsencrypt frontend add --backend-url=http://localhost:6300  --port=80 --name=http
```
### Add backend

```bash
 haproxy-letsencrypt backend add --backend-url=http://localhost:6300 --frontend=http --host=example.com -a=192.168.1.47:9000 
```

### Backend with basic auth

```bash
printf "123456" | mkpasswd --stdin --method=md5
haproxy-letsencrypt backend add --backend-url=http://localhost:6300 --frontend=http --host=example.com -a=192.168.1.47:8080 --basic-auth="foo:\$1\$IBZn5tWj\$dJIVwHaK465qDTISvMFmK1"
curl --user foo:123456 -H 'Host:example.com' localhost -v
```

## Now with ssl

```bash
haproxy-letsencrypt frontend add --backend-url=http://localhost:6300  --port=443 --name=https --ssl
```

```bash
haproxy-letsencrypt backend add --backend-url=http://localhost:6300 --frontend=https --host=example.com -a=192.168.1.47:9000
```


