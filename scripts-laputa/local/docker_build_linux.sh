#!/bin/bash
docker run --rm -it -v $(pwd):/home/ubuntu/linux-laputa -w /home/ubuntu/linux-laputa --user "$(id -u):$(id -g)" 1197744123/laputa:v1  ./scripts-laputa/local/build_linux.sh
