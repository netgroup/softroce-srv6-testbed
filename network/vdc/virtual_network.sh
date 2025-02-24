#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# author: Andrea Mayer <andrea.mayer@uniroma2.it>
# author: Paolo Lungaroni <paolo.lungaroni@uniroma2.it>
#
#
# The purpose of this script is to create and configure a virtual
# "datacenter" network with the topology already illustrated in Stefano's
# diagram (for which we are preparing a "neat" version with explanations on how
# the network is programmed and how the SRv6/IPv6 tunnels are created).
#
# To understand the "many" details of how to create L3 VPNs using SRv6/IPv6 with
# compressed SIDs, you can also refer to [1].
#
# Specifically, the script creates an IPv6 underlay network and an SRv6/IPv6
# overlay network using compressed SIDs, where the various nodes are programmed
# to perform different actions:
#
#  *) gw: these nodes are the gateways to/from the IPv4 network that
#     receives/sends traffic from/to the sender/receiver through the
#     bluefield (bf).
#     The task of a gw node is to encapsulate/decapsulate plain IPv4 traffic
#     carried by SRv6/IPv6. All tunnels are *without* SRH, but we directly use
#     only the external IPv6, encoding the network functions through the
#     compressed SIDs stored in the IPv6 Destination Address (DA).
#
#     For example, an IPv6 tunnel that encapsulates IPv4 traffic received from
#     gw1 and directed to gw2, passing through the router rt1, will have
#     the IPv6 DA set as follows:
#
#
#     IPv6 DA = fcf0:0000:00b1:000e:00a2:00d4::
#                          \______/  \______/
#                   1st node (b1) +    2nd node (a2) +
#                       func (0e)      func (d4)
#
#     where:
#      *) b1:0e = Locator-Node function, where node b1 (corresponding to
#                 rt1) advances to the next compressed SID;
#      *) a2:d4 = Locator-Node function, where node a2 (corresponding to
#                 gw2) decapsulates the IPv4 traffic carried in the IPv6
#                 tunnel.
#
#     In detail, a gw:
#      - upon receiving plain IPv4 traffic from a node, encapsulates the traffic
#        in an IPv6 tunnel and routes it to one of the adjacent routers (rt1
#        or rt2) based on the specific encapsulation policy of that tunnel;
#        for example, the first compressed SID allows reaching the specific
#        router (rt) and performs an advancement to the next compressed SID;
#      - upon receiving SRv6/IPv6 traffic, decapsulates the traffic carried in
#        the tunnel through an SRv6 End.DT4 behavior.
#        For example, an SRv6 End.DT4 behavior associated with the compressed
#        SID fcf0:0:a2:d4::/48 removes the external IPv6 header and forwards
#        the internal IPv4 traffic on the bf interface that connects it to the
#        receiver.
#
#  *) rt: these are the router nodes (rt) that receive SRv6/IPv6 traffic and
#     process it, advancing to the next compressed SID (an operation performed
#     through SRv6 End behavior with a next-csid flavor).
#     For example, an SRv6 End behavior with a next-csid flavor associated with
#     the compressed SID fcf0:0:b1:0e::/48, receiving IPv6 traffic with
#     DA=fcf0:0:b1:0e:a2:d4::, updates the IPv6 DA by consuming b1:e and
#     obtaining a new IPv6 DA=fcf0:0:a2:d4::.
#
#     The IPv6 traffic is then routed towards the node: fcf0:0:a2::/48,
#     reaching the gateway gw2.
#
#
# Topology of virtual datacenter network
# ======================================
#
# +-------+       +-------+
# |       |       |       |
# |  rt1  |       |  rt2  |
# |       |       |       |
# +---+---+       +---+---+
#     |  .         .  |
#     |    .     .    |
#     |      . .      |
#     |      . .      |
#     |    .     .    |
#     |  .         .  |
#     |.             .|
# +---+---+       +---+---+
# |       |       |       |
# |  gw1  |       |  gw2  |
# |       |       |       |
# +---+---+       +---+---+
#     |               |
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#     |               |        this part is not configured
# +---+----+     +----+-----+  in this script.
# | sender |     | receiver |
# +--------+     +----------+
#
#
# [1] - https://elixir.bootlin.com/linux/v6.13.3/source/tools/testing/selftests/net/srv6_end_next_csid_l3vpn_test.sh

set -eu
set -x

readonly TMUX=vnet

# NOTE: names can only be [a-z]+
readonly NS_GW_PREFIX="gw"
readonly NS_RT_PREFIX="rt"

# gateway and router names are encoded in an IPv6 addr using the following:
readonly IPV6_GW="a"
readonly IPV6_RT="b"

build_ns_name()
{
	local pref="${1}"
	local id="${2}"

	echo "${pref}${id}"
}

# network namespace names
# DO NOT change the order!!!
readonly NSNAMES=(
	"$(build_ns_name "${NS_GW_PREFIX}" 1)"
	"$(build_ns_name "${NS_RT_PREFIX}" 1)"
	"$(build_ns_name "${NS_RT_PREFIX}" 2)"
	"$(build_ns_name "${NS_GW_PREFIX}" 2)"
	# add new namespaces here below
)

readonly NS_GW1="${NSNAMES[0]}"
readonly NS_RT1="${NSNAMES[1]}"
readonly NS_RT2="${NSNAMES[2]}"
readonly NS_GW2="${NSNAMES[3]}"

# set MTU for virtual "datacenter" network
readonly VDC_MTU=9000

# mellanox interfaces
readonly MLX_IFNAME_GW1="ens9np0"
readonly MLX_IFNAME_GW2="ens10np1"

# SID settings
readonly LOCALSID_TABLE_ID=90
readonly LOCALSID_POLR_PRIO=999

readonly SRV6_LOCATOR_SERVICE="fcf0:0"
readonly SRV6_USID_LCBLOCK_LEN=32
readonly SRV6_USID_NODE_LEN=16
readonly SRV6_USID_FUNC_LEN=16
readonly SRV6_USID_NODE_FUNC_LEN="$((SRV6_USID_NODE_LEN + SRV6_USID_FUNC_LEN))"
readonly SRV6_USID_LOCNODE_LEN="$((SRV6_USID_LCBLOCK_LEN + SRV6_USID_NODE_LEN))"
readonly SRV6_USID_LCBLOCK_NODE_FUNC_LEN="$((SRV6_USID_LOCNODE_LEN + \
					     SRV6_USID_FUNC_LEN))"
readonly SRV6_DT4_FUNC="d4"
readonly SRV6_END_FUNC="e"

# underlay network settings
readonly IPV6_BASE="fd00"
readonly IPV6_BASE_PLEN=64
readonly IPV6_GW_HOST=1
readonly IPV6_RT_HOST=2
readonly VRF_TID="100"
readonly VRF_DEVNAME="vrf-${VRF_TID}"
readonly DUMMY_DEVNAME="dum0"

# access IPv4 network
readonly IPV4_BASE="10.55"
readonly IPV4_BASE_PLEN=24

# access IPv6 network (for test only)
readonly IPV6_TEST_BASE="2001:db8"

# Kill pending tmux session
tmux kill-session -t "${TMUX}" 2>/dev/null || true

cleanup()
{
	# move back mellanox devices before destroying netns
	ip -netns "${NS_GW1}" \
		link set dev "${MLX_IFNAME_GW1}" netns 1 || true
	ip -netns "${NS_GW2}" \
		link set dev "${MLX_IFNAME_GW2}" netns 1 || true

	for ns in "${NSNAMES[@]}"; do
		ip netns del "${ns}" || true
	done
}

#trap cleanup ERR

create_veth_peer_name()
{
	local ns1="${1}"
	local ns2="${2}"
	local devname

	devname="veth-${ns1}-${ns2}"
	echo "${devname}"
}

netns_name_extract_id()
{
	local ns="${1}"

	echo "${ns}" | sed -E 's/[a-z]+([0-9]+)/\1/g'
}

nsname_to_ipv6_id()
{
	local ns="${1}"
	local out=''

	case "${ns}" in
	"${NS_GW_PREFIX}"*)
		out=${IPV6_GW}$(netns_name_extract_id "${ns}")
		;;
	"${NS_RT_PREFIX}"*)
		out="${IPV6_RT}$(netns_name_extract_id "${ns}")"
		;;
	*)
		echo "Invalid network namespace ${ns}"
		exit 1
	esac

	echo "${out}"
}

__has_nsname()
{
	local name="${2}"
	local ns="${1}"

	# shellcheck disable=SC2053
	if [[ ("${ns}" == ${name}) ]]; then
		return 0
	fi

	return 1
}

is_gateway()
{
	local ns="${1}"
	local rc

	__has_nsname "${ns}" "${NS_GW_PREFIX}*" && rc=0 || rc="${?}"
	return "${rc}"
}

is_router()
{
	local ns="${1}"
	local rc

	__has_nsname "${ns}" "${NS_RT_PREFIX}*" && rc=0 || rc="${?}"
	return "${rc}"
}

check_link_nsnames()
{
	local n1="${1}"
	local n2="${2}"


	if ( is_gateway "${n1}" && is_router "${n2}" ) || \
	   ( is_gateway "${n2}" && is_router "${n1}" ); then
		return 0
	fi

	return 1
}

ipv6_net_prefix_from_nsnames()
{
	local n1="${1}"
	local n2="${2}"
	local p="${n1}"
	local q="${n2}"
	local p_id
	local q_id
	local net

	if ! is_gateway "${p}"; then
		p="${n2}"
		q="${n1}"
	fi

	p_id="$(nsname_to_ipv6_id "${p}")"
	q_id="$(nsname_to_ipv6_id "${q}")"
	net="${IPV6_BASE}:${p_id}:${q_id}"

	echo "${net}"
}

set_addrs_gw_rt_pairs()
{
	local gw_ns="${1}"
	local rt_ns="${2}"
	local dev_gw
	local dev_rt
	local addr

	# build device names
	dev_gw="$(create_veth_peer_name "${gw_ns}" "${rt_ns}")"
	dev_rt="$(create_veth_peer_name "${rt_ns}" "${gw_ns}")"

	addr="$(ipv6_net_prefix_from_nsnames "${gw_ns}" "${rt_ns}")"

	ip -netns "${gw_ns}" addr \
		add "${addr}::${IPV6_GW_HOST}/${IPV6_BASE_PLEN}" dev "${dev_gw}"
	ip -netns "${rt_ns}" addr \
		add "${addr}::${IPV6_RT_HOST}/${IPV6_BASE_PLEN}" dev "${dev_rt}"
}

add_link_gw_rt_pairs()
{
	local ns1="${1}"
	local ns2="${2}"
	local dev_ns1
	local dev_ns2

	dev_ns1="$(create_veth_peer_name "${ns1}" "${ns2}")"
	dev_ns2="$(create_veth_peer_name "${ns2}" "${ns1}")"

	ip -netns "${ns1}" link \
		add "${dev_ns1}" \
		type veth \
		peer name "${dev_ns2}" \
		netns "${ns2}"

	# set mtu
	ip -netns "${ns1}" link set "${dev_ns1}" mtu "${VDC_MTU}"
	ip -netns "${ns2}" link set "${dev_ns2}" mtu "${VDC_MTU}"

	ip -netns "${ns1}" link set "${dev_ns1}" up
	ip -netns "${ns2}" link set "${dev_ns2}" up

	set_addrs_gw_rt_pairs "${ns1}" "${ns2}"
}

add_links_gw_rt_neighs()
{
	local rt_neighs="${2}"
	local gw="${1}"
	local neigh

	for neigh in ${rt_neighs}; do
		add_link_gw_rt_pairs "${gw}" "${neigh}"
	done
}

setup_gw()
{
	local phydev=${2}
	local gw="${1}"
	local gw_id

	ip -netns "${gw}" link \
		add "${VRF_DEVNAME}" type vrf table "${VRF_TID}"

	# set the VRF strict mode for allowing End.DT4 to process SRv6 packets
	ip netns exec "${gw}" \
		sh -c "echo 1 > /proc/sys/net/vrf/strict_mode"

	ip -netns "${gw}" link set dev "${VRF_DEVNAME}" up

	# move the physical interface inside the gw net namespace
	ip link set dev "${phydev}" netns "${gw}"

	# enslave the physical interface connecting the host with the gw to the
	# VRF and then set the IPv4 address.
	ip -netns "${gw}" link \
		set dev "${phydev}" master "${VRF_DEVNAME}"

	gw_id="$(netns_name_extract_id "${gw}")"
	ip -netns "${gw}" addr \
		add "${IPV4_BASE}.${gw_id}.254/${IPV4_BASE_PLEN}" \
		dev "${phydev}"

	# for test only
	ip -netns "${gw}" addr \
		add "${IPV6_TEST_BASE}:${gw_id}::254/${IPV6_BASE_PLEN}" \
		dev "${phydev}"

	ip -netns "${gw}" link set dev "${phydev}" up
}

setup_rt()
{
	local rt="${1}"

	# create dummy device used as dev for SRv6 End behaviors
	ip -netns "${rt}" link \
		add "${DUMMY_DEVNAME}" type dummy

	ip -netns "${rt}" link set dev "${DUMMY_DEVNAME}" mtu "${VDC_MTU}"
	ip -netns "${rt}" link set dev "${DUMMY_DEVNAME}" up
}

setup_sid_reachability()
{
	local neighs="${2}"
	local nexthop_host
	local net_prefix
	local neigh_ipv6
	local ns="${1}"
	local devname
	local neigh

	if is_gateway "${ns}"; then
		# our neigh is a router, so nexthop is set with the router
		# "host" part in the ipv6 address
		nexthop_host="${IPV6_RT_HOST}"
	elif is_router "${ns}"; then
		nexthop_host="${IPV6_GW_HOST}"
	else
		# BUG, unexpected nsname
		exit 1
	fi

	for neigh in ${neighs}; do
		net_prefix="$(ipv6_net_prefix_from_nsnames "${ns}" "${neigh}")"
		devname="$(create_veth_peer_name "${ns}" "${neigh}")"
		neigh_ipv6="$(nsname_to_ipv6_id "${neigh}")"

		# underlay network for SID reachability
		ip -netns "${ns}" -6 route \
			add "${SRV6_LOCATOR_SERVICE}:${neigh_ipv6}::/${SRV6_USID_LOCNODE_LEN}" \
			table "${LOCALSID_TABLE_ID}" \
			via "${net_prefix}::${nexthop_host}"
	done
}

setup_gw_local_sids()
{
	local rt_neighs="${2}"
	local gw_ipv6_id
	local gw="${1}"

	setup_sid_reachability "${gw}" "${rt_neighs}"

	gw_ipv6_id="$(nsname_to_ipv6_id "${gw}")"

	# Configure SRv6 End.DT4
	ip -netns "${gw}" -6 route \
		add "${SRV6_LOCATOR_SERVICE}:${gw_ipv6_id}:${SRV6_DT4_FUNC}::/${SRV6_USID_LCBLOCK_NODE_FUNC_LEN}" \
		table "${LOCALSID_TABLE_ID}" \
		encap seg6local action End.DT4 \
		vrftable "${VRF_TID}" \
		count \
		dev "${VRF_DEVNAME}"

	# set default route to unreachable
	ip -netns "${gw}" -6 route \
		add unreachable default metric 4278198272 \
		vrf "${VRF_DEVNAME}"

	# all sids start with a common locator
	ip -netns "${gw}" -6 rule \
		add to "${SRV6_LOCATOR_SERVICE}::/${SRV6_USID_LCBLOCK_LEN}" \
		lookup "${LOCALSID_TABLE_ID}" \
		prio "${LOCALSID_POLR_PRIO}"
}

setup_rt_local_sids()
{
	local gw_neighs="${2}"
	local rt_ipv6_id
	local rt="${1}"

	setup_sid_reachability "${rt}" "${gw_neighs}"

	rt_ipv6_id="$(nsname_to_ipv6_id "${rt}")"

	ip -netns "${rt}" -6 route \
		add "${SRV6_LOCATOR_SERVICE}:${rt_ipv6_id}:${SRV6_END_FUNC}::/${SRV6_USID_LCBLOCK_NODE_FUNC_LEN}" \
		table "${LOCALSID_TABLE_ID}" \
		encap seg6local action End \
		flavors next-csid \
		lblen "${SRV6_USID_LCBLOCK_LEN}" \
		nflen "${SRV6_USID_NODE_FUNC_LEN}" \
		count \
		dev "${DUMMY_DEVNAME}"

	# all sids start with a common locator
	ip -netns "${rt}" -6 rule \
		add to "${SRV6_LOCATOR_SERVICE}::/${SRV6_USID_LCBLOCK_LEN}" \
		lookup "${LOCALSID_TABLE_ID}" \
		prio "${LOCALSID_POLR_PRIO}"
}

setup_srv6_l3_tunnel()
{
	# shellcheck disable=SC2206
	local nodelist=(${2})
	local ipv6_node_id
	local nssrc="${1}"
	local gw_decap_id
	local carrier=''
	local num_nodes
	local ipv4_net
	local func
	local node
	local i

	if ! is_gateway "${nssrc}"; then
		echo "${nssrc} must be a gateway"
		exit 1
	fi

	num_nodes="${#nodelist[@]}"
	if [ "${num_nodes}" -lt 2 ]; then
		echo "nodelist must contain 2 nodes at least"
		exit 1
	fi

	carrier="${SRV6_LOCATOR_SERVICE}"

	for ((i=0; i < num_nodes; ++i)); do
		node="${nodelist[${i}]}"
		ipv6_node_id="$(nsname_to_ipv6_id "${node}")"
		carrier="${carrier}:${ipv6_node_id}"

		if ( is_router "${node}" ) && (( i < num_nodes - 1 )); then
			func="${SRV6_END_FUNC}"
		elif ( is_gateway "${node}" ) && (( i == num_nodes - 1 )); then
			func="${SRV6_DT4_FUNC}"
			gw_decap_id="$(netns_name_extract_id "${node}")"
		else
			echo "Invalid node list"
			exit 1
		fi

		carrier="${carrier}:${func}"
	done

	# fill the carrier with trailing zeros
	carrier="${carrier}::"
	ipv4_net="${IPV4_BASE}.${gw_decap_id}.0/${IPV4_BASE_PLEN}"

	ip -netns "${nssrc}" -4 route \
		add "${ipv4_net}" \
		vrf "${VRF_DEVNAME}" \
		encap seg6 \
		mode encap.red \
		segs "${carrier}" \
		dev "${VRF_DEVNAME}"
}

setup_network()
{
	# build the network links connecting gateways and routers;
	# add veth pairs links e.g., veth-gw1-rt1 <-> veth-rt1-gw1
	add_links_gw_rt_neighs "${NS_GW1}" "${NS_RT1} ${NS_RT2}"
	add_links_gw_rt_neighs "${NS_GW2}" "${NS_RT1} ${NS_RT2}"

	# setup gateways
	setup_gw "${NS_GW1}" "${MLX_IFNAME_GW1}"
	setup_gw "${NS_GW2}" "${MLX_IFNAME_GW2}"
	# setup routers
	setup_rt "${NS_RT1}"
	setup_rt "${NS_RT2}"

	# setup gw local sids
	setup_gw_local_sids "${NS_GW1}" "${NS_RT1} ${NS_RT2}"
	setup_gw_local_sids "${NS_GW2}" "${NS_RT1} ${NS_RT2}"
	# setup rt local sids
	setup_rt_local_sids "${NS_RT1}" "${NS_GW1} ${NS_GW2}"
	setup_rt_local_sids "${NS_RT2}" "${NS_GW1} ${NS_GW2}"

	# setup srv6 tunnels
	setup_srv6_l3_tunnel "${NS_GW1}" \
			     "${NS_RT1} ${NS_GW2}"
	setup_srv6_l3_tunnel "${NS_GW2}" \
			     "${NS_RT2} ${NS_GW1}"
}

create_netns() {
	for ns in "${NSNAMES[@]}"; do
		ip netns add "${ns}"

		# always set lo up once as soon as the netns is created
		ip -netns "${ns}" link set dev lo up

		# a bunch of sysctl parameters to be set in each netns
		ip netns exec "${ns}" \
			sysctl -w net.ipv4.conf.all.forwarding=1
		ip netns exec "${ns}" \
			sysctl -w net.ipv6.conf.all.forwarding=1

		ip netns exec "${ns}" \
			sysctl -w net.ipv4.conf.all.rp_filter=0
		# in this way no need to set rp_filter for every add/new netdev
		ip netns exec "${ns}" \
			sysctl -w net.ipv4.conf.default.rp_filter=0

		ip netns exec "${ns}" \
			sysctl -wq net.ipv6.conf.all.accept_dad=0
		ip netns exec "${ns}" \
			sysctl -wq net.ipv6.conf.default.accept_dad=0
	done

	setup_network
}

setup_tmux()
{
	local ns
	local i

	# create a new tmux session
	tmux new-session -d \
		-s "${TMUX}" \
		-n "${NSNAMES[0]}" \
		ip netns exec "${NSNAMES[0]}" bash -c \
			"env PS1='${NSNAMES[0]}:\w> ' bash --norc"

	for ((i=1; i < ${#NSNAMES[@]}; ++i)); do
		ns="${NSNAMES[${i}]}"

		# create a tmux window attached to the existing session
		tmux new-window -t "${TMUX}" \
			-n "${ns}" \
			ip netns exec "${ns}" bash -c \
				"env PS1='${ns}:\w> ' bash --norc"
	done

	tmux set-option -g mouse on
	tmux select-window -t :0
	tmux attach -t "${TMUX}"
}

cleanup
create_netns
setup_tmux
