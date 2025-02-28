compile:
	bash -c "source ../tools/set_sde.bash && ~/tools/p4_build.sh --with-p4c=bf-p4c /root/P4_CCA_ID/p4src/basic.p4"

run:
	bash -c "source ../tools/set_sde.bash && pkill switchd 2> /dev/null && cd /root/bf-sde-9.6.0/ && ./run_switchd.sh -p basic"

conf_links:
	bash -c "source ../tools/set_sde.bash && cd /root/bf-sde-9.6.0/ && ./run_bfshell.sh --no-status-srv -f /root/P4_CCA_ID/ucli_cmds"

control_rules:
	bash -c "source ../tools/set_sde.bash && /root/bf-sde-9.6.0/run_bfshell.sh --no-status-srv -i -b /root/P4_CCA_ID/bfrt_python/setup.py"
