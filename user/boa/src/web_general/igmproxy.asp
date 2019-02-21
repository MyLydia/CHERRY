<%SendWebHeadStr(); %>
<title><% multilang(LANG_IGMP_PROXY); %><% multilang(LANG_CONFIGURATION); %></title>

<SCRIPT>
var multicast_allow=0;
var robust_count=0;
var last_member_query_count=0;
var query_interval=0;
var query_response_interval=0;
var group_leave_delay=0;
var multi_wan_proxy=0;
<% igmpproxyinit(); %>
function on_init()
{
	with(document.forms[0])
	{
		if(multicast_allow == 0)
			igmp_multicast_allow[0].checked = true;
		else
			igmp_multicast_allow[1].checked = true;
		igmp_robust_count.value = robust_count;
		igmp_last_member_query_count.value = last_member_query_count;
		igmp_query_interval.value = query_interval;
		igmp_query_response_interval.value = query_response_interval;
		igmp_group_leave_delay.value = group_leave_delay;
	}
	if(multi_wan_proxy == 1)
	{
	   document.getElementById("proxy_enable").style="display:none";
	   document.getElementById("proxy_intf").style="display:none";
	 }
	 else
	 {
	   document.getElementById("proxy_enable").style="display:";
	   document.getElementById("proxy_intf").style="display:";
	  }
	proxySelection();
}
function proxySelection()
{
	if (document.igmp.proxy[0].checked && multi_wan_proxy == 0) {
		document.igmp.proxy_if.disabled = true;
		document.igmp.igmp_multicast_allow[0].disabled = true;
		document.igmp.igmp_multicast_allow[1].disabled = true;
		document.igmp.igmp_robust_count.disabled = true;
		document.igmp.igmp_last_member_query_count.disabled = true;
		document.igmp.igmp_query_interval.disabled = true;
		document.igmp.igmp_query_response_interval.disabled = true;
		document.igmp.igmp_group_leave_delay.disabled = true;
	}
	else {
		document.igmp.proxy_if.disabled = false;
		document.igmp.igmp_multicast_allow[0].disabled = false;
		document.igmp.igmp_multicast_allow[1].disabled = false;
		document.igmp.igmp_robust_count.disabled = false;
		document.igmp.igmp_last_member_query_count.disabled = false;
		document.igmp.igmp_query_interval.disabled = false;
		document.igmp.igmp_query_response_interval.disabled = false;
		document.igmp.igmp_group_leave_delay.disabled = false;
	}
}

function on_submit()
{
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	return true;
}
</SCRIPT>
</head>

<body>
<div class="intro_main ">
	<p class="intro_title"><% multilang(LANG_IGMP_PROXY); %> <% multilang(LANG_CONFIGURATION); %></p>
	<p class="intro_content"> <% multilang(LANG_IGMP_PROXY_ENABLES_THE_SYSTEM_TO_ISSUE_IGMP_HOST_MESSAGES_ON_BEHALF_OF_HOSTS_THAT_THE_SYSTEM_DISCOVERED_THROUGH_STANDARD_IGMP_INTERFACES_THE_SYSTEM_ACTS_AS_A_PROXY_FOR_ITS_HOSTS_WHEN_YOU_ENABLE_IT_BY_DOING_THE_FOLLOWS); %>:
    <br>. <% multilang(LANG_ENABLE_IGMP_PROXY_ON_WAN_INTERFACE_UPSTREAM_WHICH_CONNECTS_TO_A_ROUTER_RUNNING_IGMP); %>
    <br>. <% multilang(LANG_ENABLE_IGMP_ON_LAN_INTERFACE_DOWNSTREAM_WHICH_CONNECTS_TO_ITS_HOSTS); %></p>
</div>

<form action=/boaform/formIgmproxy method=POST name="igmp">
<div class="data_common data_common_notitle">
	<table>
		<tr id="proxy_enable">
			<th><% multilang(LANG_IGMP_PROXY); %>:</th>
			<td>
				<input type="radio" value="0" name="proxy" <% checkWrite("igmpProxy0"); %> onClick="proxySelection()"><% multilang(LANG_DISABLE); %>&nbsp;&nbsp;
				<input type="radio" value="1" name="proxy" <% checkWrite("igmpProxy1"); %> onClick="proxySelection()"><% multilang(LANG_ENABLE); %>
			</td>
		</tr>
		<tr id="proxy_intf">
			<th><% multilang(LANG_PROXY_INTERFACE); %>:</th>
			<td>
				<select name="proxy_if" <% checkWrite("igmpProxy0d"); %>>
			  		<% if_wan_list("rt"); %>
				</select>
			</td>
		</tr>
		<tr>
			<th>Multicast Allowed:</th>
			<td>
				<input type="radio" value="0" name="igmp_multicast_allow"><% multilang(LANG_DISABLE); %>
				<input type="radio" value="1" name="igmp_multicast_allow"><% multilang(LANG_ENABLE); %>
			</td>
		</tr>
		<tr>
			<th>Robust Count:</th>
			<td>
				<input type="text" name="igmp_robust_count" size="10" maxlength="15">
			</td>
		</tr>
		<tr>
			<th>Last Member Query Count:</th>
			<td>
				<input type="text" name="igmp_last_member_query_count" size="10" maxlength="15">
			</td>
		</tr>
		<tr>
			<th>Query Interval:</th>
			<td>
				<input type="text" name="igmp_query_interval" size="10" maxlength="15">(seconds)
			</td>
		</tr>
		<tr>
			<th>Query Response Interval:</th>
			<td>
				<input type="text" name="igmp_query_response_interval" size="10" maxlength="15">(*100ms)
			</td>
		</tr>
		<tr>
			<th>Group Leave Delay:</th>
			<td>
				<input type="text" name="igmp_group_leave_delay" size="10" maxlength="15">(ms)
			</td>
		</tr>
	</table>
</div>

<div class="btn_ctl">
	<input class="link_bg" type="submit" value="<% multilang(LANG_APPLY_CHANGES); %>" onClick="return on_submit()">
	<input type="hidden" value="/igmproxy.asp" name="submit-url">
	<input type="hidden" name="postSecurityFlag" value="">
</div>
<script>
	ifIdx = <% getInfo("igmp-proxy-itf"); %>;
	if (ifIdx != 255)
		document.igmp.proxy_if.value = ifIdx;
	else
		document.igmp.proxy_if.selectedIndex = 0;
	on_init();
</script>
</form>
</body>

</html>
