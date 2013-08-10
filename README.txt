For this project it is recomended to run it on a fresh ubuntu install

$ make

it will make the module and you will have to load the module
ports=#
will be the port number you want to block you can have multiple by doing
ports=#,#,#
up to 10 max

to block port 80 and 22

$ sudo insmod drop.ko ports=80,22


to see output

$ tail -f /var/log/kern.log

to stop the firewall
$ sudo rmmod drop

