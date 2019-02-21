<%SendWebHeadStr(); %>
<title>MLD Proxy</title>
<title><% multilang(LANG_MLD_PROXY); %><% multilang(LANG_CONFIGURATION); %></title>
<SCRIPT>
var robust_count=0;
var query_interval=0;
var query_response_interval=0;
var last_member_query_response_interval=0;
var multi_wan_proxy=0;
<% mldproxyinit(); %>
function on_init()
{
	with(document.forms[0])
	{
		mld_robust_count.value = robust_count;	
		mld_query_interval.value = query_interval;
		mld_query_response_interval.value = query_response_interval;
		mld_last_member_query_response_interval.value = last_member_query_response_interval;
	}	
}
function proxySelection()
{
	if(document.mldproxy.daemon[0].checked && (multi_wan_proxy==0))
	{
		document.mldproxy.ext_if.disabled = true;
		document.mldproxy.mld_robust_count.disabled = true;
		document.mldproxy.mld_query_interval.disabled = true;
		document.mldproxy.mld_query_response_interval.disabled = true;
		document.mldproxy.mld_last_member_query_response_interval.disabled = true;
	}
	else
	{
		document.mldproxy.ext_if.disabled = false;
		document.mldproxy.mld_robust_count.disabled = false;
		document.mldproxy.mld_query_interval.disabled = false;
		document.mldproxy.mld_query_response_interval.disabled = false;
		document.mldproxy.mld_last_member_query_response_interval.disabled = false;
	}
	if(multi_wan_proxy == 1)
	{
	   document.getElementById("proxy_enable").style="display:none";
	   document.getElementById("proxy_wan_if").style="display:none";
	 }
	 else
	 {
	   document.getElementById("proxy_enable").style="display:";
	   document.getElementById("proxy_wan_if").style="display:";
	 }
}

function on_submit()
{
	document.forms[0].save.isclick = 1;
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	return true;
}
</SCRIPT>
</HEAD>

<body>
<div class="intro_main ">
	<p class="intro_title"><% multilang(LANG_MLD_PROXY); %> <% multilang(LANG_CONFIGURATION); %></p>
	<p class="intro_content"><% multilang(LANG_THIS_PAGE_BE_USED_TO_CONFIGURE_MLD_PROXY); %></p>
</div>

<form id="form" action=/boaform/admin/formMLDProxy method=POST name="mldproxy">
	<div class="data_common data_common_notitle">			
		<table>
			<tr id="proxy_enable">
				<th><% multilang(LANG_MLD_PROXY); %>:</th>
				<td>
				<input type="radio" value="0" name="daemon" <% checkWrite("mldproxy0"); %> onClick="proxySelection()"><% multilang(LANG_DISABLE); %>&nbsp;&nbsp;
				<input type="radio" value="1" name="daemon" <% checkWrite("mldproxy1"); %> onClick="proxySelection()"><% multilang(LANG_ENABLE); %></td>
			</tr>
			<tr id="proxy_wan_if">
				<th><% multilang(LANG_WAN_INTERFACE); %>:&nbsp;</th>
				<td><select name="ext_if" <% checkWrite("mldproxy0d"); %>> <% if_wan_list("rtv6"); %> </select> </td>
			</tr>
			<tr>
				<th>Robust Count:</th>
				<td>
					<input type="text" name="mld_robust_count" size="10" maxlength="15">
				</td>
			</tr>
			<tr>
				<th>Query Interval:</th>
				<td>
					<input type="text" name="mld_query_interval" size="10" maxlength="15">(Second)
				</td>
			</tr>
			<tr>
				<th>Query Response Interval:</th>
				<td>
					<input type="text" name="mld_query_response_interval" size="10" maxlength="15">(millisecond)
				</td>
			</tr>
			<tr>
				<th>Response Interval of Last Group Member:</th>
				<td>
					<input type="text" name="mld_last_member_query_response_interval" size="10" maxlength="15">(Second)
				</td>
			</tr>
		</table>
	</div>
	<div class="btn_ctl">			
		<input class="link_bg" type="submit"  value="<% multilang(LANG_APPLY_CHANGES); %>" name="save" onClick="return on_submit()">
		<input type="hidden" value="/app_mldProxy.asp" name="submit-url">
		<input type="hidden" name="postSecurityFlag" value="">
	</div>
</form>

<script>
	on_init();
	initUpnpDisable = document.mldproxy.daemon[0].checked;
	ifIdx = <% getInfo("mldproxy-ext-itf"); %>;
	document.mldproxy.ext_if.selectedIndex = -1;
	for( i = 0; i < document.mldproxy.ext_if.options.length; i++ )
	{
		if( ifIdx == document.mldproxy.ext_if.options[i].value )
			document.mldproxy.ext_if.selectedIndex = i;
	}
	proxySelection();
</script>
<br><br>
</body>
</html>
