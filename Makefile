up:
	docker run   -d   -v ./vector.yaml:/etc/vector/vector.yaml:ro  -v /var/log/nginx/access.log:/var/log/nginx/access.log  -p 8686:8686   --name vector-1   timberio/vector:0.46.1-debian
down:
	docker stop vector-1 && docker rm vector-1
apply:
	docker restart vector-1
