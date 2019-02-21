<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<!--系统默认模板-->
<html>
<head>
<title>中国移动—时间管理服务器</title>
<meta http-equiv=pragma content=no-cache>
<meta http-equiv=cache-control content="no-cache, must-revalidate">
<meta http-equiv=content-type content="text/html; charset=gbk">
<meta http-equiv=content-script-type content=text/javascript>
<!--系统公共css-->
<style type=text/css>
@import url(/style/default.css);
</style>
<!--系统公共脚本-->
<script language="javascript" src="common.js"></script>
<script language="javascript" type="text/javascript">

var ntpServers = new Array();
var voiceName = "<% getInfo("voiceName"); %>";

ntpServers.push("clock.fmt.he.net");
ntpServers.push("clock.nyc.he.net");
ntpServers.push("clock.sjc.he.net");
ntpServers.push("clock.via.net");
ntpServers.push("ntp1.tummy.com");
ntpServers.push("time.cachenetworks.com");
ntpServers.push("time.nist.gov");

function ntpChange(optionlist, textbox)
{
	if (document.forms[0].ntpEnabled.checked)
	{
		if( optionlist.value == "Other" )
		{
			textbox.disabled = false;
		}
		else
		{
			textbox.value = "";
			textbox.disabled = true;
		}	
	}	
}

function ntpEnblChange()
{
	if (document.forms[0].ntpEnabled.checked)
		status = 'visible';
	else
		status = 'visible';   //others alway visible

	if (document.getElementById)
		document.getElementById('ntpConfig').style.visibility = status;
	else if (!document.layers)
		document.all.ntpConfig.style.visibility = status;
		
	if (!document.forms[0].ntpEnabled.checked)	
		document.getElementById('ntpTZ').style.visibility = 'hidden';
	else
		document.getElementById('ntpTZ').style.visibility = status;
}

function writeNtpList(select, other, server, needed)
{
	var flag = 0;

	if (!needed)
		select.add(new Option("None"));

	for (var i = 0; i < ntpServers.length; i++) {
		if (server.value == ntpServers[i]) {
			select.add(new Option(ntpServers[i], ntpServers[i], true, true));
			flag = 1;
		} else {
			select.add(new Option(ntpServers[i]));
		}
	}

	if (flag || !needed && server.value.length == 0) {
		select.add(new Option("Other"));
		other.disabled = true;
		other.value = "";
	} else {
		select.add(new Option("Other", "Other", true, true));
		other.disabled = false;
		other.value = server.value;
	}
}

function sntp_init()
{
	var select1 = document.getElementById("ntpServerHost1");
	var select2 = document.getElementById("ntpServerHost2");
	var if_type_voip = document.forms[0].if_type.options[1];
	
	if (document.forms[0].ntpEnabled.checked)
	{
		document.getElementById("ntpServerOther1").disabled = false;
		document.getElementById("ntpServerOther2").disabled = true;
	}
	else
	{
		document.getElementById("ntpServerOther1").disabled = false;
		document.getElementById("ntpServerOther2").disabled = false;	
		document.getElementById("ntpServerOther1").value = select1.value;	
		document.getElementById("ntpServerOther2").value = select2.value;		
	}

	if_type_voip.text = voiceName;
}

function if_typeChange()
{
	var if_type = document.forms[0].if_type.value;
	var if_wan = document.forms[0].if_wan;
	var keyword, i;
	
	switch (if_type) {
		case "0":
			keyword = "INTERNET";
			break;
		case "1":
			keyword = voiceName;
			break;
		case "2":
			keyword = "TR069";
			break;
		case "3":
		default:
			keyword = "Other";
			break;
	}

	for (i = 0; i < if_wan.options.length; i++) {
		if (if_wan.options[i].text.search(keyword) == -1) {
			//if_wan.options[i].style.display = "none";		//this is not workable with IE
			if_wan.options[i].disabled = true;
		} else {
			//if_wan.options[i].style.display = "block";
			if_wan.options[i].disabled = false;
		}
	}

	/* deselect when the previous selected interface does not match the new selected if_type */
	if (if_wan.selectedIndex == -1 || (if_wan.selectedIndex >= 0 && if_wan.options[if_wan.selectedIndex].text.search(keyword) == -1))
	{
		if_wan.selectedIndex = -1;

		/* Find first available interface */
		for (i = 0; i < if_wan.options.length; i++)
		{
			if (if_wan.options[i].text.search(keyword) > 0)
				if_wan.selectedIndex = i;
		}
	}
}

/********************************************************************
**          on document submit
********************************************************************/
function on_submit()
{
	var select1 = document.getElementById("ntpServerHost1");
	var srv1 = select1.options[select1.selectedIndex].text;
	var select2 = document.getElementById("ntpServerHost2");
	var srv2 = select2.options[select2.selectedIndex].text;
	with (document.forms[0]) {
		if (ntpEnabled.checked) {
			if (srv1 == "Other") {
				if (ntpServerOther1.value.length == 0) {	// == Other
					alert
					    ('主SNTP服务器设置为其他，但其他栏为空。');
					return;
				} else {
					server1.value = document.timeZone.ntpServerOther1.value;
				}
			} else {
				server1.value = srv1;
			}

			if (srv2 == "Other") {
				if (ntpServerOther2.value.length == 0) {	// == Other
					alert
					    ('从SNTP服务器设置为其他，但其他栏为空。');
					return;
				} else {
					server2.value = ntpServerOther2.value;
				}
			} else {
				if (ntpServerHost2.selectedIndex > 0)
					server2.value = srv2;
				else
					server2.value = "";
			}

			if (interval.value == 0) {
				alert("同步间隔设置不可为 0。");
				return;
			}
		}
	}
}

</script>
</head>

<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000" onload="sntp_init()">
	<blockquote>
	<div align="left" style="padding-left:20px; padding-top:10px">
	  <form action=/boaform/admin/formTimezone method=POST name="timeZone" id="timeZone">
		SNTP开关<input type='checkbox' name='ntpEnabled' onClick='ntpEnblChange()'>
		<br>
		<div id='ntpConfig'>
		  <table border="0" cellpadding="0" cellspacing="0">
		  	<tr>
			  <td width='150'>&nbsp;系統日期时间:</td>
			  <td colspan=2>
			  	<% getInfo("year"); %>年<% getInfo("month"); %>月<% getInfo("day"); %>日<% getInfo("hour"); %>时<% getInfo("minute"); %>分
			  </td>
			</tr>
			<tr>
			  <td width='150'>&nbsp;绑定的WAN连接:</td>
			  <td colspan=2>
			  <select name='if_type' onClick='if_typeChange()'>
				<option value = "0" selected>INTERNET</option>
				<option value = "1">VOIP</option>
				<option value = "2">TR069</option>
				<option value = "3">Other</option>
			  </select>
			  </td>
			</tr>
			<tr>
			  <td width='150'>&nbsp;主SNTP服务器:</td>
			  <td width="250">
			  <select id='ntpServerHost1' name='ntpServerHost1' size="1" onChange='ntpChange(ntpServerHost1, ntpServerOther1)'>
			  </select>
			  </td>
			  <td>
			  <input type="text" maxlength=63 name='ntpServerOther1' id='ntpServerOther1'></td>
			</tr>
			<tr>
			  <td>&nbsp;从SNTP服务器:</td>
			  <td>
			  <select id='ntpServerHost2' name='ntpServerHost2' size="1" onChange='ntpChange(ntpServerHost2, ntpServerOther2)'>
			  </select>
			  </td>  
			  <td>
			  <input  type="text" maxlength=63 name='ntpServerOther2' id='ntpServerOther2'></td>
			</tr>
		  </table>
		  <table border="0" cellpadding="0" cellspacing="0">
			<tr>
			  <td width='150'>&nbsp;同步间隔:</td>
			  <td colspan=2><input type='text' name='interval'> s</td>
			</tr>
			<td style="display:none;" 'width='150' value="同步的WAN连接:"></td>
			  <select style="display:none;" name="if_wan">
			  <% if_wan_list("rt"); %>
			  </select>
		  </table>
		  <br>
		  <br><br>
		</div>
		<div id='ntpTZ'>
			<tr>
			  <td width='150'>&nbsp;时间区域:</td>
			  <br><br><td colspan=2>&nbsp;
			  <select name='tmzone' size="1">
				  <% timeZoneList(); %>
			  </select>
			  </td>
			</tr>
		</div>
		<br><br><br><br><br>
		<input type='hidden' name="server1" value="">
		<input type='hidden' name="server2" value="">
		<input type="hidden" name="submit-url" value="/net_sntp_cmcc.asp">
		<div><tr><center>			
		<input class="btnsaveup" type="submit" value="确定" onClick="on_submit();">&nbsp;&nbsp;
		<input type="button" class="btnsaveup2" value="取消" onclick="window.location.reload()">
		</center></tr></div>
		</form>	
	  <script language="javascript">
		  with (document.forms[0]) {
			  <% init_sntp_page(); %>
			  writeNtpList(ntpServerHost1, ntpServerOther1, server1, true);
			  writeNtpList(ntpServerHost2, ntpServerOther2, server2, false);
			  ntpEnblChange();
		  }
	  </script>
	  </div>
	</blockquote>
</body>
<%addHttpNoCache();%>
</html>
