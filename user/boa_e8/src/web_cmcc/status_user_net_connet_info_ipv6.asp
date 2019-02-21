<!-- add by liuxiao 2008-01-16 -->
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<html>
<head>
<title>中国移动</title>
<meta http-equiv=pragma content=no-cache>
<meta http-equiv=cache-control content="no-cache, must-revalidate">
<meta http-equiv=content-type content="text/html; charset=gbk">
<meta http-equiv="refresh" content="5">
<meta http-equiv=content-script-type content=text/javascript>
<style type=text/css>
@import url(/style/default.css);
</style>
<script language="javascript" src="common.js"></script>
<SCRIPT language="javascript" type="text/javascript">
var links = new Array();
<% listWanConfigIpv6(); %>
/********************************************************************
**          on document load
********************************************************************/
function on_init()
{
	if(links.length > 0)
	{
		lstrc.deleteRow(1);
		secondrc.deleteRow(1);
		thirdrc.deleteRow(1);
		net_info.deleteRow(1);
	}

	if(lstrc.rows){while(lstrc.rows.length > 2) lstrc.deleteRow(2);}
	for(var i = 0; i < links.length; i++)
	{
		var row = lstrc.insertRow(i + 1);
		
		row.nowrap = true;
		row.vAlign = "top";
		row.align = "center";
		row.className = "hdt";

		var cell = row.insertCell(0);
		cell.innerHTML =(links[i].servName==""?"-":links[i].servName);
		cell = row.insertCell(1);
		cell.innerHTML =(links[i].strStatus==""?"-":links[i].strStatus);
		cell = row.insertCell(2);
		cell.innerHTML =(links[i].ipv6Addr==""?"-":links[i].ipv6Addr);
		cell = row.insertCell(3);
		cell.innerHTML =(links[i].ipv6Gateway==""?"-":links[i].ipv6Gateway);

	}

	
	if(secondrc.rows){while(secondrc.rows.length > 2) secondrc.deleteRow(2);}
	for(var i = 0; i < links.length; i++)
	{
		var row = secondrc.insertRow(i + 1);
		
		row.nowrap = true;
		row.vAlign = "top";
		row.align = "center";
		row.className = "hdt";

		var cell = row.insertCell(0);
		cell.innerHTML = (links[i].servName==""?"-":links[i].servName);
		
		cell = row.insertCell(1);
		cell.innerHTML = links[i].ipv6PrefixOrigin ? "手动":"自动";

		cell = row.insertCell(2);
		if(links[i].protocol=="br1483")
			cell.innerHTML="-";
		else
			cell.innerHTML = (links[i].protocol==""?"-":links[i].protocol);
	}

	if(thirdrc.rows){while(thirdrc.rows.length > 2) thirdrc.deleteRow(2);}
	for(var i = 0; i < links.length; i++)
	{
		var row = thirdrc.insertRow(i + 1);
		
		row.nowrap = true;
		row.vAlign = "top";
		row.align = "center";
		row.className = "hdt";

		var cell = row.insertCell(0);
		cell.innerHTML = (links[i].servName==""?"-":links[i].servName);
		cell = row.insertCell(1);
		cell.innerHTML = ((links[i].vlanId + "/" + links[i].vprio)=="/"?"-":(links[i].vlanId + "/" + links[i].vprio));
		cell = row.insertCell(2);
		cell.innerHTML = (links[i].MacAddr==""?"-":links[i].MacAddr);
   }
	
	if(net_info.rows){while(net_info.rows.length > 2) net_info.deleteRow(2);}
	for(var i = 0; i < links.length; i++)
	{
		var row = net_info.insertRow(i + 1);
		
		row.nowrap = true;
		row.vAlign = "top";
		row.align = "center";
		row.className = "hdt";

		var cell = row.insertCell(0);
		cell.innerHTML = (links[i].servName==""?"-":links[i].servName);
		cell = row.insertCell(1);
		cell.innerHTML = (links[i].ipv6Dns1==""?"-":links[i].ipv6Dns1);
		cell = row.insertCell(2);
		cell.innerHTML = (links[i].ipv6Dns2==""?"-":links[i].ipv6Dns2);
		cell = row.insertCell(3);
		cell.innerHTML = (links[i].ipv6Prefix==""?"-":links[i].ipv6Prefix);
}
}

</SCRIPT>

</head>
<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000" onLoad="on_init();">
	<blockquote>
			<br>
			<table class="flat" id="lstrc" border="1" cellpadding="1" cellspacing="1" width="100%">	    
				<tr class="hdb" align="center" nowrap>
					<td width="20%">连接名称</td>
					<td>连接状态</td>
					<td>IP地址</td>
					<td>IPv6默认网关</td>
				</tr>
	     		<tr class="hdt" align="center" nowrap>
					<td width="20%">-</td>
					<td>-</td>
					<td>-</td>
					<td>-</td>
				</tr>

			</table>

			<br><br>
			<table class="flat" id="secondrc" border="1" cellpadding="1" cellspacing="1" width="100%">
				<tr class="hdb" align="center" nowrap>
					<td width="20%">连接名称</td>
					<td>前缀获取方式</td>
					<td>IP获取方式</td>
				</tr>
				<tr class="hdt" align="center" nowrap>
					<td width="20%">-</td>
					<td>-</td>
					<td>-</td>
				</tr>

			</table>
			<br><br>
			
			<table class="flat" id="thirdrc" border="1" cellpadding="1" cellspacing="1" width="100%">
				<tr class="hdb" align="center" nowrap>
					<td width="20%">连接名称</td>
					<td>VLAN/优先级</td>
					<td>MAC地址</td>
				</tr>
				<tr class="hdt" align="center" nowrap>
					<td width="20%">-</td>
					<td>-</td>
					<td>-</td>
				</tr>

			</table>

			<br><br>
			<table class="flat" id="net_info" border="1" cellpadding="1" cellspacing="1" width="100%">
				<tr class="hdb" align="center" nowrap>
					<td width="20%">连接名称</td>
					<td>IPv6首选DNS</td>
					<td>IPv6备用DNS</td>
					<td>前缀</td>
				</tr>
				<tr class="hdt" align="center" nowrap>
					<td width="20%">-</td>
					<td>-</td>
					<td>-</td>
					<td>-</td>
				</tr>


			</table>
	</blockquote>
</body>
<%addHttpNoCache();%>
</html>
