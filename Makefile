install:
	go build -o haproxy-letsencrypt main.go
	sudo mv haproxy-letsencrypt /usr/local/bin/