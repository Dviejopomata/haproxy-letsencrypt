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
haproxy-letsencrypt frontend add --backend-url=http://localhost:6300  --address=*:80 --name=http
```
### Add backend

```bash
 haproxy-letsencrypt backend add --backend-url=http://localhost:6300 --frontend=http --host=example.com -a=192.168.1.47:9000 
```


## Now with ssl

```bash
haproxy-letsencrypt frontend add --backend-url=http://localhost:6300  --port=443 --name=https --ssl
```

```bash
haproxy-letsencrypt backend add --backend-url=http://localhost:6300 --frontend=https --host=example.com -a=192.168.1.47:9000
```
