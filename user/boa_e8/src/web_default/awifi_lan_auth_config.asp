<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<html>
<head>
<title>�й�����</title>
<meta http-equiv=pragma content=no-cache>
<meta http-equiv=cache-control content="no-cache, must-revalidate">
<meta http-equiv=content-type content="text/html; charset=gbk">
<style type=text/css>
@import url(/style/default.css);
</style>
<script language="javascript" src="common.js"></script>
<script language="javascript" type="text/javascript">
var cgi = new Object();
<%initAwifiLanAuth();%>

//var old_lan_ip = null;

/********************************************************************
**          on document load
********************************************************************/

function on_init()
{
	sji_docinit(document, cgi);
	if(document.AwifiLanAuth.awifiLanEnabled.checked){
		document.AwifiLanAuth.lan1port.checked = true;
		document.AwifiLanAuth.lan1port.disabled = true;
		document.AwifiLanAuth.lan2port.checked = true;
		document.AwifiLanAuth.lan2port.disabled = true;
		document.AwifiLanAuth.lan3port.checked = true;
		document.AwifiLanAuth.lan3port.disabled = true;
		document.AwifiLanAuth.lan4port.checked = true;
		document.AwifiLanAuth.lan4port.disabled = true;
	}
//	old_lan_ip = document.forms[0].uIp.value;
}

function awifiLanStart() 
{	
	if(document.AwifiLanAuth.awifiLanEnabled.checked){
		document.AwifiLanAuth.lan1port.checked = true;
		document.AwifiLanAuth.lan1port.disabled = true;
		document.AwifiLanAuth.lan2port.checked = true;
		document.AwifiLanAuth.lan2port.disabled = true;
		document.AwifiLanAuth.lan3port.checked = true;
		document.AwifiLanAuth.lan3port.disabled = true;
		document.AwifiLanAuth.lan4port.checked = true;
		document.AwifiLanAuth.lan4port.disabled = true;
	}
	else{
		document.AwifiLanAuth.lan1port.disabled = false;
		document.AwifiLanAuth.lan1port.checked = false;
		document.AwifiLanAuth.lan2port.disabled = false;
		document.AwifiLanAuth.lan2port.checked = false;
		document.AwifiLanAuth.lan3port.disabled = false;
		document.AwifiLanAuth.lan3port.checked = false;
		document.AwifiLanAuth.lan4port.disabled = false;
		document.AwifiLanAuth.lan4port.checked = false;
	}
}

function isSameSubNet(lan1Ip, lan1Mask, lan2Ip, lan2Mask)
{
	var count = 0;

	lan1a = lan1Ip.split(".");
	lan1m = lan1Mask.split(".");
	lan2a = lan2Ip.split(".");
	lan2m = lan2Mask.split(".");

	for (i = 0; i < 4; i++)
	{
		l1a_n = parseInt(lan1a[i]);
		l1m_n = parseInt(lan1m[i]);
		l2a_n = parseInt(lan2a[i]);
		l2m_n = parseInt(lan2m[i]);
		if ((l1a_n & l1m_n) == (l2a_n & l2m_n))
			count++;
	}
	if (count == 4)
		return true;
	else
		return false;
}
function on_submit(reboot)
{
	if(reboot)
	{
		var loc = "mgm_dev_reboot.asp";
		var code = "location.assign(\"" + loc + "\")";
		eval(code);
	}
	else
	{
		with ( document.forms[0] )
		{
			if ( sji_checkvip(uIp.value) == false )
			{
				uIp.focus();
				alert("IP��ַ \"" + uIp.value + "\" ����Ч��IP��ַ.");
				return;
			}
			if ( sji_checkmask(uMask.value) == false )
			{
				uMask.focus();
				alert("�������� \"" + uMask.value + "\" ����Ч����������.");
				return;
			}

			if (sji_checkvip(dhcpRangeStart.value) == false || !(isSameSubNet(uIp.value, uMask.value, dhcpRangeStart.value, uMask.value)))
			{
				dhcpRangeStart.focus();
				alert("��ʼIP��ַ\"" + dhcpRangeStart.value + "\"����ЧIP��ַ.");
				return;
			}
			if ( sji_checkvip(dhcpRangeEnd.value) == false || !(isSameSubNet(uIp.value, uMask.value, dhcpRangeEnd.value, uMask.value)))
			{
				dhcpRangeEnd.focus();
				alert("��ֹIP��ַ\"" + dhcpRangeEnd.value + "\"����ЧIP��ַ.");
				return;
			}
			if (sji_ipcmp(dhcpRangeStart.value, dhcpRangeEnd.value) > 0)
			{
				alert("��ֹIP��ַ������ڻ���ڳ�ʼIP��ַ.");
				return;
			}

			lan1a = dhcpRangeStart.value.split(".");
			lan2a = dhcpRangeEnd.value.split(".");
			l1a_n = parseInt(lan1a[3]);
			l2a_n = parseInt(lan2a[3]);
			if(l1a_n != 51){
				dhcpRangeStart.focus();
				alert("��ʼIP��ַ����λ������51.");
				return;
			}
			if(l2a_n != 250){
				dhcpRangeEnd.focus();
				alert("��ֹIP��ַ����λ������250.");
				return;
			}


//			if(old_lan_ip != uIp.value)
//				alert("���Ѿ��� IP ��ַ�޸ĳ� \"" + uIp.value + "\"��֮�����ɴ� IP 				��ַ����·������Ҳ��ǵ��޸�װ�õ�DHCP��ַ���䣬ȷ������װ�ÿ���˳��������");
			postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);

			submit();
		}
	}
}
</script>
</head>
<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000" onLoad="on_init();">
<blockquote>
<form action=/boaform/formAwifiLanAuth method="post" name="AwifiLanAuth">
	<div class="text_location">
		<table>
			<tr>
				<td>����lan����֤ </td>
				<td><input name="awifiLanEnabled" id="awifiLanEnabled" onclick="awifiLanStart();" type="checkbox"></td>
			</tr>
			<tr>
				<td>IP ��ַ</td>
				<td><input type="text" name="uIp" value=<% getInfo("lan-ip2"); %>></td>
			</tr>
			<tr>
				<td>��������</td>
				<td><input type="text" name="uMask" value=<% getInfo("lan-subnet2"); %>></td>
			</tr>
			<tr>
				<td>DHCP��ʼIP</td>
			 <td>	<input type="text" name="dhcpRangeStart"></td>
			</tr>
			<tr>
				<td>DHCP����IP</td>
				<td><input type="text" name="dhcpRangeEnd"></td>
				
			</tr>
			<tr>
				<td>DHCP����ʱ��</td>
				<td>
					<select size="1" name="ulTime">
						<option value="60">һ����</option>
						<option value="1800">��Сʱ</option>
						<option value="3600">һСʱ</option>
						<option value="86400">һ��</option>
						<option value="604800">һ��</option>
					</select>
				</td>
			</tr>
			<tr>
				<td>�󶨶˿�</td>
				<td>
					<input name="lan1port" type="checkbox"> LAN1
					<input name="lan2port" type="checkbox"> LAN2
				</td>
			</tr>
			<tr>
				<td></td>
				<td>
					<input name="lan3port" type="checkbox"> LAN3
					<input name="lan4port" type="checkbox"> LAN4
				</td>
			</tr>
			<tr>
				<td></td>
				<td>
					<input name="ssid1port" type="checkbox"> chinanetSSID1
					<input name="ssid2port" type="checkbox" checked  disabled="true"> aWiFiSSID2
				</td>
			</tr>
			<tr>
				<td>
					<input name="savebtn" class="button" onclick="on_submit(0);" value="����" type="button">
					<input type="hidden" name="submit-url" value="/awifi_lan_auth_config.asp">
					<input type="hidden" name="postSecurityFlag" value="">
				</td>
			</tr>
		</table>		
		
	</div>
</form>
</blockquote>
</body>
<%addHttpNoCache();%>
<script>
</script>
</html>
