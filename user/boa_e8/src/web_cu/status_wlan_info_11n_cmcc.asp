<!-- add by liuxiao 2008-01-21 -->
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

var rcs = new Array();
<% wlStatsList(); %>
var wlDefChannel=new Array();
var wlan_root_interface_up = new Array();
<% wlan_interface_status(); %>
var Band2G5GSupport=new Array();
var wlan_parm = new Array();
<% wlStatus_parm(); %>

/********************************************************************
**          on document load
********************************************************************/
function on_init()
{
	if (lsteth.rows) {
		while (lsteth.rows.length > 2)
			lsteth.deleteRow(2);
	}

	for (var i = 0; i < rcs.length; i++) {
		var row = lsteth.insertRow(i + 2);

		row.nowrap = true;
		//row.style.verticalAlign = "top";
		row.style.textAlign = "center";

		var cell = row.insertCell(0);
		cell.innerHTML = rcs[i].ifname;
		cell = row.insertCell(1);
		cell.innerHTML = rcs[i].rx_packets;
		cell = row.insertCell(2);
		cell.innerHTML = rcs[i].rx_bytes;
		cell = row.insertCell(3);
		cell.innerHTML = rcs[i].rx_errors;
		cell = row.insertCell(4);
		cell.innerHTML = rcs[i].rx_dropped;
		cell = row.insertCell(5);
		cell.innerHTML = rcs[i].tx_packets;
		cell = row.insertCell(6);
		cell.innerHTML = rcs[i].tx_bytes;
		cell = row.insertCell(7);
		cell.innerHTML = rcs[i].tx_errors;
		cell = row.insertCell(8);
		cell.innerHTML = rcs[i].tx_dropped;
	}
	
	if (wl_settings.rows) {
		while (wl_settings.rows.length > 1)
			wl_settings.deleteRow(1);
	}
	
	var len = 0;
	for (var i = 0; i < wlan_parm.length; i++) {

			var row = wl_settings.insertRow(len + 1);

			row.nowrap = true;
			//row.style.verticalAlign = "top";
			row.style.textAlign = "center";
			
			var cell = row.insertCell(0);
			cell.innerHTML = "SSID-" + wlan_parm[i].ssid_idx;
			cell = row.insertCell(1);
			cell.innerHTML = wlan_parm[i].ssid;
			cell = row.insertCell(2);
			cell.innerHTML = (wlan_parm[i].encrypt_state) ? "������": "δ����";
			cell = row.insertCell(3);
			cell.innerHTML = wlan_parm[i].auth_mode;
			cell = row.insertCell(4);
			cell.innerHTML = wlan_parm[i].encrypt_mode;
			len ++;
	}
}

var wlan_num = <% checkWrite("wlan_num"); %>;

var wlan_module_enable = <% checkWrite("wlan_module_enable"); %>;

   
</script>
</head>
<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000" onLoad="on_init();">
	<blockquote>
		<div align="left" style="padding-left:20px;"><br>
			<div align="left"><b>WLAN�ӿ���Ϣ��</b></div>
			<div align="left" style="width:768px;"><br>
			<table class="flat" border="1" cellpadding="0" cellspacing="1" width="90%">
<script>


document.write('\
<tr>\
<td width="20%" class="hdb">�������翪��״̬</td>\
<td class="hdt" width="80%">');
if(!wlan_module_enable)
	document.write('ͣ��');
else
	document.write('����');
document.write(	'</td></tr>');

if(wlan_module_enable){

for(i=0; i < wlan_num; i++){

		if(wlan_root_interface_up[i]){
			if(wlan_num==1){
				document.write('<tr><td class="hdb">�ŵ�</td><td class="hdt">'+wlDefChannel[i]+'</td></tr>');
			}
			else{
				if(Band2G5GSupport[i] == 1)
				document.write('<tr><td class="hdb">2.4GHz �ŵ�</td><td class="hdt">'+wlDefChannel[i]+'</td></tr>');
				else
				document.write('<tr><td class="hdb">5GHz �ŵ�</td><td class="hdt">'+wlDefChannel[i]+'</td></tr>');
			}
		}

	}
}
</script>
			</table>
			</div>
		</div>
		<br><br>
		<div align="left" style="padding-left:20px;">
			<div align="left"><b>�����������ã�</b></div>
			<br>
			<table id="wl_settings" class="flat" border="1" cellpadding="1" cellspacing="1" width="100%">
			<tr class="hdb" align="center" nowrap>
			<td width="20%">SSID����</td>
			<td width="20%">SSID����</td>
			<td width="20%">��ȫ����</td>
			<td width="20%">��֤��ʽ</td>
			<td width="20%">����</td>
			</tr>
			</table>
		</div>
		<br><br>
		<div align="left" style="padding-left:20px;">
			<div align="left"><b>�շ��������</b></div>
			<br>
			<table id="lsteth" class="flat" border="1" cellpadding="1" cellspacing="1" width="100%">
			   <tr class="hdb" align="center" nowrap>
					<td>�ӿ�</td>
					<td colspan="4">����</td>
					<td colspan="4">����</td>
				</tr>
			   <tr class="hdb" align="center" nowrap>
					<td>&nbsp;</td>
					<td>��</td>
					<td>�ֽ�</td>
					<td>����</td>
					<td>����</td>
					<td>��</td>
					<td>�ֽ�</td>
					<td>����</td>
					<td>����</td>
				</tr>
			</table>
		</div>
	</blockquote>
</body>
<!-- add end by liuxiao 2008-01-21 -->
<%addHttpNoCache();%>
</html>
