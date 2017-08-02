.PHONY: default
default: bw ;

bwpy-environ:
	$(CC) -O3 bwpy-mount-wrapper.c -o bwpy-environ
	sudo chown root:root bwpy-environ
	sudo chmod +s bwpy-environ

jyc:
	$(CC) -O3 -DCONFIG_TYPE=CONFIG_JYC bwpy-mount-wrapper.c -o bwpy-environ
	sudo chown root:root bwpy-environ
	sudo chmod +s bwpy-environ

bw:
	$(CC) -O3 -DCONFIG_TYPE=CONFIG_BW bwpy-mount-wrapper.c -o bwpy-environ
	sudo chown root:root bwpy-environ
	sudo chmod +s bwpy-environ

test:
	$(CC) -O3 -DCONFIG_TYPE=CONFIG_TEST bwpy-mount-wrapper.c -o bwpy-environ
	sudo chown root:root bwpy-environ
	sudo chmod +s bwpy-environ

clean:
	rm -f bwpy-environ

