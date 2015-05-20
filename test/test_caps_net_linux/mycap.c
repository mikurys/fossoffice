/**

Build and run as:

gcc mycap.c -lcap -o mycap.o ; echo 'Please run as root command: setcap cap_net_admin+eip cap_net_raw+eip on this program compiled here, and press enter when ready' ; read _ ; echo 'CAPs set on the file are:' ; /sbin/getcap ./mycap.o ; echo "===" ; ./mycap.o ; echo '=== Trying to access /dev/net/tun/' ; cat /dev/net/tun || echo "### CAN NOT ACCESS THIS FILE ###" ; echo '=== stat on it: ' ; stat /dev/net/tun ; echo "=== mount: " ; mount ; echo "Current dir was mounted on: " ; df -h . 


(the problem seems explained now - for example it was the nosuid flag in mount!) <------------------------------- !

Example run from computer that has the problem:

CAPs set on the file are:
./mycap.o = cap_net_admin,cap_net_raw+eip
===
Starting on Linux 3.2.69-grsec-mempo.deskmax.0.2.126 #1 SMP PREEMPT Tue May 19 20:30:51 UTC 2015 x86_64
cap_chown            0          flags:           EFFECTIVE OK    PERMITTED -     INHERITABLE -    
cap_setfcap          31         flags:           EFFECTIVE -     PERMITTED -     INHERITABLE OK   
cap_mac_admin        33         flags:           EFFECTIVE -     PERMITTED OK    INHERITABLE -    
This are all enabled caps
Tried to change caps, result: -2
Tried to open tun, allocated fd=-1 (### FAILURE ###) <------------------------------------
=== Trying to access /dev/net/tun/
cat: /dev/net/tun: File descriptor in bad state <------------ still unexplained(?)
### CAN NOT ACCESS THIS FILE ###
=== stat on it: 
  File: `/dev/net/tun'
  Size: 0               Blocks: 0          IO Block: 4096   character special file
Device: 5h/5d   Inode: 4114        Links: 1     Device type: a,c8
Access: (1666/crw-rw-rwT)  Uid: (    0/    root)   Gid: (    0/    root)
Access: 2015-05-20 15:18:18.738693154 +0200
Modify: 2015-05-20 15:18:18.738693154 +0200
Change: 2015-05-20 15:18:18.738693154 +0200
 Birth: -
=== mount: 
(...)
/dev/mapper/vg_tsl2-lv_home2 on /homebig type ext4 (rw,nosuid,nodev,noatime,user_xattr,barrier=1,data=ordered,usrquota,grpquota)
/dev/mapper/vg_tesla-lv_var on /var type ext4 (rw,noatime,user_xattr,barrier=1,data=ordered,usrquota,grpquota)
proc on /sid-root/proc type proc (rw,relatime)
sysfs on /sid-root/sys type sysfs (rw,relatime)
rpc_pipefs on /var/lib/nfs/rpc_pipefs type rpc_pipefs (rw,relatime)
binfmt_misc on /proc/sys/fs/binfmt_misc type binfmt_misc (rw,nosuid,nodev,noexec,relatime)
Current dir was mounted on: 
Filesystem                    Size  Used Avail Use% Mounted on
/dev/mapper/vg_XXX2-lv_home2  XXXT  XXXT  XXXG 90% /homebig


*/


#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>

#include <sys/socket.h> 

#include <linux/ioctl.h>

#include <linux/if.h>
#include <linux/if_tun.h>

#include <sys/types.h>
#include <sys/capability.h>

#include <stdio.h>
#include <sys/utsname.h>

// THE MAIN TEST:
int tun_alloc(char *dev) {
	struct ifreq ifr;
	int fd, err;

	if( (fd = open("/dev/net/tun", O_RDWR)) < 0 ) {
	return -1;
	}
	//        return tun_alloc_old(dev);

	memset(&ifr, 0, sizeof(ifr));

	/* Flags: IFF_TUN   - TUN device (no Ethernet headers) 
	*        IFF_TAP   - TAP device  
	*
	*        IFF_NO_PI - Do not provide packet information  
	*/ 
	ifr.ifr_flags = IFF_TUN; 
	//      if( *dev ) strncpy(ifr.ifr_name, dev, IFNAMSIZ);

	int x = TUNSETIFF;

	if( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ) {
	 close(fd);
	 return err;
	}


	//    strcpy(dev, ifr.ifr_name);

	return fd;
}              


int prepare_cap() {
	cap_t caps;
	cap_value_t cap_list[2];
	caps = cap_get_proc();

	if (caps == NULL) return -10;

	cap_list[0] = CAP_NET_ADMIN;
	//cap_list[1] = CAP_NET_RAW;

	if (cap_set_flag(caps, CAP_EFFECTIVE, 1, cap_list, CAP_SET) == -1) return -1;
	if (cap_set_proc(caps) == -1) return -2;
	if (cap_free(caps) == -1) return -3;
	return 0;
}

int list_cap() {
 pid_t pid;
 cap_t cap;
 cap_value_t cap_list[CAP_LAST_CAP+1];
 cap_flag_t cap_flags;
 cap_flag_value_t cap_flags_value;
 
 //
 // GENERATE THIS LIST ON YOUR SYSTEM BEFORE RUNNING:
 //
 // generated list with command line below:
 // sed -n 's/^#define \(CAP_.*\) .*/\1/p' /usr/include/linux/capability.h | tr A-Z a-z | sed -e 's/^\([a-z_]*\).*$/"\1",/g'
 //
 
 const char *cap_name[CAP_LAST_CAP+1] = {
"cap_chown",
"cap_dac_override",
"cap_dac_read_search",
"cap_fowner",
"cap_fsetid",
"cap_kill",
"cap_setgid",
"cap_setuid",
"cap_setpcap",
"cap_linux_immutable",
"cap_net_bind_service",
"cap_net_broadcast",
"cap_net_admin",
"cap_net_raw",
"cap_ipc_lock",
"cap_ipc_owner",
"cap_sys_module",
"cap_sys_rawio",
"cap_sys_chroot",
"cap_sys_ptrace",
"cap_sys_pacct",
"cap_sys_admin",
"cap_sys_boot",
"cap_sys_nice",
"cap_sys_resource",
"cap_sys_time",
"cap_sys_tty_config",
"cap_mknod",
"cap_lease",
"cap_audit_write",
"cap_audit_control",
"cap_setfcap",
"cap_mac_override",
"cap_mac_admin",
"cap_syslog",
"cap_wake_alarm"
 // "cap_last_cap",
 };
 
 pid = getpid();
 cap = cap_get_pid(pid);
 if (cap == NULL) {
  perror("cap_get_pid");
  exit(-1);
 }
 
 /* effetive cap */
 cap_list[0] = CAP_CHOWN;
 if (cap_set_flag(cap, CAP_EFFECTIVE, 1, cap_list, CAP_SET) == -1) {
  perror("cap_set_flag cap_chown");
  cap_free(cap);
  exit(-1);
 }
 
 /* permitted cap */
 cap_list[0] = CAP_MAC_ADMIN;
 if (cap_set_flag(cap, CAP_PERMITTED, 1, cap_list, CAP_SET) == -1) {
  perror("cap_set_flag cap_mac_admin");
  cap_free(cap);
  exit(-1);
 }
 
 /* inherit cap */
 cap_list[0] = CAP_SETFCAP;
 if (cap_set_flag(cap, CAP_INHERITABLE, 1, cap_list, CAP_SET) == -1) {
  perror("cap_set_flag cap_setfcap");
  cap_free(cap);
  exit(-1);
 }
 
        /* dump them */
 int i;
 for (i=0; i < CAP_LAST_CAP ; i++) {
  cap_from_name(cap_name[i], &cap_list[i]);

	cap_get_flag(cap, cap_list[i], CAP_EFFECTIVE, &cap_flags_value);
	int is_e = (cap_flags_value == CAP_SET);

  cap_get_flag(cap, cap_list[i], CAP_PERMITTED, &cap_flags_value);
	int is_p = (cap_flags_value == CAP_SET);
	
  cap_get_flag(cap, cap_list[i], CAP_INHERITABLE, &cap_flags_value);
	int is_i = (cap_flags_value == CAP_SET);

	if (is_e || is_p || is_i) {
	  printf("%-20s %d\t\t", cap_name[i], cap_list[i]);
	  printf("flags: \t\t");
	  printf(" EFFECTIVE %-4s ",   (is_e) ? "OK" : "-");
	  printf(" PERMITTED %-4s ",   (is_p) ? "OK" : "-");
	  printf(" INHERITABLE %-4s ", (is_i) ? "OK" : "-");
	  printf("\n");
	}
 }
 printf("This are all enabled caps\n");
 
 cap_free(cap);
 
 return 0;
}

 

int main(int argc, char **argv) {
	struct utsname unameData;
	uname(&unameData);
	printf("Starting on %s %s %s %s\n", unameData.sysname, unameData.release, unameData.version, unameData.machine);

	char *name = NULL;
	if (argc>=2) name=argv[1];

	int listed = list_cap();

	int caps = prepare_cap();
	printf("Tried to change caps, result: %d\n", caps);

	int fd = tun_alloc(name);
	printf("Tried to open tun, allocated fd=%d (%s)\n", fd,  (fd>0 ? "===SUCCESS===" : "### FAILURE ###") );
}

