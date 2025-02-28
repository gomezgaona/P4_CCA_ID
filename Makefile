#P4_CCA_ID
setup:
	cd /root/bf-sde-9.6.0/ ; sh . ../tools/./set_sde.bash
	
compile:
	~/tools/p4_build.sh --with-p4c=bf-p4c /root/P4_CCA_ID/p4src/basic.p4

run:
	pkill switchd 2> /dev/null ; cd /root/bf-sde-9.6.0/ ;./run_switchd.sh -p basic

conf_links:
	cd /root/bf-sde-9.6.0/ ; ./run_bfshell.sh --no-status-srv -f /root/P4_CCA_ID/ucli_cmds

start_control_plane_measurements:
	/root/bf-sde-9.6.0/./run_bfshell.sh --no-status-srv -i -b /root/P4_CCA_ID/bfrt_python/control_plane.py