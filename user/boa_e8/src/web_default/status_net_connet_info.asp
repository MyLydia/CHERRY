<!-- add by liuxiao 2008-01-16 -->
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<html>
<head>
<title>�й�����</title>
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
<% listWanConfig(); %>
/********************************************************************
**          on document load
********************************************************************/
function on_init()
{
	if(lstrc.rows){while(lstrc.rows.length > 1) lstrc.deleteRow(1);}
	for(var i = 0; i < links.length; i++)
	{
		var row = lstrc.insertRow(i + 1);

		row.nowrap = true;
		row.vAlign = "top";
		row.align = "center";

		var cell = row.insertCell(0);
		cell.innerHTML = links[i].servName;
		cell = row.insertCell(1);
		cell.innerHTML = links[i].vlanId;
		cell = row.insertCell(2);
//		cell.innerHTML = links[i].servType;
//		cell = row.insertCell(3);
//		cell.innerHTML = links[i].encaps;
//		cell = row.insertCell(4);
		cell.innerHTML = links[i].protocol;
		cell = row.insertCell(3);
		cell.innerHTML = links[i].igmpEnbl ? "����" : "����";
		cell = row.insertCell(4);
		cell.innerHTML = links[i].strStatus;
		cell = row.insertCell(5);
		cell.innerHTML = links[i].ipAddr;
		cell = row.insertCell(6);
		cell.innerHTML = links[i].netmask;
	}

	if(net_info.rows){while(net_info.rows.length > 1) net_info.deleteRow(1);}
	for(var i = 0; i < links.length; i++)
	{
		var row = net_info.insertRow(i + 1);

		row.nowrap = true;
		row.vAlign = "top";
		row.align = "center";

		var cell = row.insertCell(0);
		cell.innerHTML = links[i].servName;
		cell = row.insertCell(1);
		cell.innerHTML = links[i].gateway;
		cell = row.insertCell(2);
		cell.innerHTML = links[i].dns1;
		cell = row.insertCell(3);
		cell.innerHTML = links[i].dns2;
	}
}

</SCRIPT>

</head>
<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000" onLoad="on_init();">
	<blockquote>
		<div align="left" style="padding-left:20px;"><br>
			<div align="left"><b>WAN��Ϣ</b></div>
			<table class="flat" id="lstrc" border="1" cellpadding="1" cellspacing="1" width="90%">
				<tr class="hdb" align="center" nowrap>
					<td>����ӿ�</td>
					<td>VLAN ID</td>
					<!-- td>�������</td>
					<td>��װ��ʽ</td -->
					<td>Э��</td>
					<td>IGMP</td>
					<td>״̬</td>
					<td>IP��ַ</td>
					<td>��������</td>
				</tr>
			</table>
			<br><br>
			<b>������Ϣ</b>
			<br>
			<table class="flat" id="net_info" border="1" cellpadding="1" cellspacing="1" width="90%">
				<tr class="hdb" align="center" nowrap>
					<td>����ӿ�</td>
					<td>ȱʡ����</td>
					<td>��ѡDNS������</td>
					<td>����DNS������</td>
				</tr>
			</table>
		</div>
	</blockquote>
</body>
<%addHttpNoCache();%>
</html>
