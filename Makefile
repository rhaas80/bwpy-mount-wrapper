.PHONY: default
default: bwpy-environ ;

bwpy-environ:
	$(CC) -O3 bwpy-mount-wrapper.c main.c -o bwpy-environ
	sudo chown root:root bwpy-environ
	sudo chmod +s bwpy-environ

jyc:
	$(CC) -O3 -DCONFIG_TYPE=CONFIG_JYC bwpy-mount-wrapper.c main.c -o bwpy-environ
	chown root:root bwpy-environ
	chmod +s bwpy-environ

bw:
	$(CC) -O3 -DCONFIG_TYPE=CONFIG_BW bwpy-mount-wrapper.c main.c -o bwpy-environ
	chown root:root bwpy-environ
	chmod +s bwpy-environ

test:
	$(CC) -O3 -DCONFIG_TYPE=CONFIG_TEST bwpy-mount-wrapper.c main.c -o bwpy-environ
	sudo chown root:root bwpy-environ
	sudo chmod +s bwpy-environ

regtest:
	$(CC) -O3 -DCONFIG_TYPE=CONFIG_TEST bwpy-mount-wrapper.c test.c -o regtest

clean:
	rm -f bwpy-environ

