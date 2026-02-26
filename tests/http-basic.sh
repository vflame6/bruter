#!/bin/bash
# HTTP Basic Auth test using nginx
cat > /tmp/bruter-nginx.conf << 'EOF'
events {}
http {
    server {
        listen 8888;
        location / {
            auth_basic "Restricted";
            auth_basic_user_file /etc/nginx/.htpasswd;
            return 200 "OK";
        }
    }
}
EOF

# Generate htpasswd: admin:12345678
docker run --rm httpd:2.4 htpasswd -nb admin 12345678 > /tmp/bruter-htpasswd

docker run -d --name nginx-basic-auth -p 127.0.0.1:8888:8888 \
  -v /tmp/bruter-nginx.conf:/etc/nginx/nginx.conf:ro \
  -v /tmp/bruter-htpasswd:/etc/nginx/.htpasswd:ro \
  nginx:alpine

sleep 3
go run . http-basic -u tests/usernames.txt -p tests/passwords.txt -t 127.0.0.1:8888 -D

docker rm -f nginx-basic-auth
rm -f /tmp/bruter-nginx.conf /tmp/bruter-htpasswd
