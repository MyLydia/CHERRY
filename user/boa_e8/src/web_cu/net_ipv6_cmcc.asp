<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<!--ϵͳĬ��ģ��-->
<HTML>
<HEAD>
<TITLE>�й��ƶ�-DHCP</TITLE>
<META http-equiv=pragma content=no-cache>
<META http-equiv=cache-control content="no-cache, must-revalidate">
<META http-equiv=content-type content="text/html; charset=gbk">
<META http-equiv=content-script-type content=text/javascript>
<!--ϵͳ����css-->
<STYLE type=text/css>
@import url(/style/default.css);
</STYLE>
<!--ϵͳ�����ű�-->
<SCRIPT language="javascript" src="common.js"></SCRIPT>
<SCRIPT language="javascript" src="share.js"></SCRIPT>
<SCRIPT language="javascript" type="text/javascript">

var popUpWin=0;
var modeIndex;

//var cgi = new Object();

/********************************************************************
**          on document load
********************************************************************/

function on_init()
{
//	sji_docinit(document, cgi);
}

/********************************************************************
**          on document update
********************************************************************/

function popUpWindow(URLStr, left, top, width, height)
{
	if(popUpWin)
	{
		if(!popUpWin.closed) popUpWin.close();
	}
	popUpWin = open(URLStr, "popUpWin", "toolbar=yes,location=no,directories=no,status=no,menubar=yes,scrollbars=yes,resizable=yes,copyhistory=yes,width="+width+",height="+height+",left="+left+", top="+top+",screenX="+left+",screenY="+top+"");
}


/********************************************************************
**          on document submit
********************************************************************/

function prefixModeChange()
{
	with ( document.lanipv6raconfform )
	{
		var prefix_mode =ipv6lanprefixmode.value;
		
		v6delegated_WANConnection.style.display = 'none';
		staticipv6prefix.style.display = 'none';
		staticipv6prefix2.style.display = 'none';
		switch(prefix_mode){
			case '0': //WANDelegated
					v6delegated_WANConnection.style.display = 'block';
					break;
			case '1': //Static
					staticipv6prefix.style.display = 'block';
					staticipv6prefix2.style.display = 'block';
					break;
					
		}
	}
}

function dhcpChange()
{
	with ( document.lanipv6dhcpform )
	{
		var dhcp_mode =ipv6landnsconf.value;
		
		v6dhcp_WANConnectionMode.style.display = 'none';	
		v6dhcp_StaticMode.style.display = 'none';
		v6dhcp_DnsStatic.style.display = 'none';
		switch(dhcp_mode){
			case '0': //Static
					v6dhcp_StaticMode.style.display = 'block';
					v6dhcp_DnsStatic.style.display = 'block';
					break;
			case '1': //WANConnection
					v6dhcp_WANConnectionMode.style.display = 'block';
					dnsModeChange();
					break;
			case '2': //WANConnection
					v6dhcp_WANConnectionMode.style.display = 'block';
					dnsModeChange();
					break;	
		}
	}

}

function dnsModeChange()
{
	with ( document.lanipv6dhcpform )
	{
		var dns_mode =ipv6landnsmode.value;
		var dhcp_mode =ipv6landnsconf.value;
		
		v6dhcp_DnsStatic.style.display = 'none';
		
		if(dhcp_mode == 0){//static
			v6dhcp_DnsStatic.style.display = 'block';
		}
		else{
			switch(dns_mode){
			case '2': //static
					v6dhcp_DnsStatic.style.display = 'block';
					break;
			case '0': //HGWProxy
					break;
			default: //wanconnection
					break;
		}
		}
	}

}

function raCheckChange()
{
	with ( document.lanipv6raconfform )
	{
		div_ra.style.display = 'none';
		if(enableradvd.checked==true){
			div_ra.style.display = 'block';
			enableradvd.value = 1;
		}
		else{
			enableradvd.value = 0;
		}
	}
}

function dhcpv6CheckChange(modeIdx)
{
	with ( document.lanipv6dhcpform )
	{
		modeIndex = modeIdx;
		div_dhcpv6.style.display = 'none';
		div_dhcpv6_relay.style.display = 'none';
		if(modeIdx == 2){
			div_dhcpv6.style.display = 'block';
		}
		else if(modeIdx == 1){
			div_dhcpv6_relay.style.display = 'block';
		}
	}
}

function checkChange(cb)
{
	if(cb.checked==true){
		cb.value = 1;
	}
	else{
		cb.value = 0;
	}
}

//Handle Prefix v6 mode
function on_lanipv6raconfform_submit(reboot)
{
	with ( document.lanipv6raconfform )
	{
			if ( document.lanipv6raconfform.ipv6lanprefixmode.value==1){
				if(document.lanipv6raconfform.Prefix.value == "" )
				{
					document.lanipv6raconfform.Prefix.focus();
					alert("IP��ַ \"" + document.lanipv6raconfform.Prefix.value + "\" ����Ч��IPv6 Prefix ��ַ.");
					return false;
				}
				if ( document.lanipv6raconfform.Prefixlen.value < 16 ||
					document.lanipv6raconfform.Prefixlen.value >64) { //check if is valid ipv6 address
					alert("��Ч��RAǰ׺����!");	
					document.lanipv6raconfform.Prefixlen.focus();
					return false;
				}
				if ( document.lanipv6raconfform.ULAPrefixPreferedTime.value < 600 ||
					document.lanipv6raconfform.ULAPrefixPreferedTime.value >4294967295) { 
					alert("��Ч��RA��ѡ����!");	
					document.lanipv6raconfform.ULAPrefixPreferedTime.focus();
					return false;
				}
				if ( document.lanipv6raconfform.ULAPrefixValidTime.value < 600 ||
					document.lanipv6raconfform.ULAPrefixValidTime.value >4294967295) { 
					alert("��Ч��RA��Ч����!");	
					document.lanipv6raconfform.ULAPrefixValidTime.focus();
					return false;
				}
				if ( document.lanipv6raconfform.V6MinRtrAdvInterval.value < 3 ||
					document.lanipv6raconfform.V6MinRtrAdvInterval.value >1350) { 
					alert("��Ч��RA��С���!");	
					document.lanipv6raconfform.V6MinRtrAdvInterval.focus();
					return false;
				}
				if ( document.lanipv6raconfform.V6MaxRtrAdvInterval.value < 4 ||
					document.lanipv6raconfform.V6MaxRtrAdvInterval.value >1800) { 
					alert("��Ч��RA�����!");	
					document.lanipv6raconfform.V6MaxRtrAdvInterval.focus();
					return false;
				}
			}
			submit();
	}
}

//Handle DNSv6 mode
function on_lanipv6dhcpform_submit(reboot)
{

	with ( document.lanipv6dhcpform )
	{
		if(modeIndex == 1)
		{
		}	
		else if ( ipv6landnsconf.value==0 ){  //static
				if(lanIpv6dhcpprefix.value == "" )
				{
					lanIpv6dhcpprefix.focus();
					alert("IP��ַ \"" + lanIpv6dhcpprefix.value + "\" ����Ч��IPv6 Prefix ��ַ.");
					return false;
				}
				if ( lanIpv6dhcpprefixlen.value < 16 ||
					lanIpv6dhcpprefixlen.value >64) { //check if is valid ipv6 address
					alert("��Ч��ǰ׺����!");	
					lanIpv6dhcpprefixlen.focus();
					return false;
				}
				if ( lanIpv6dhcpPreferredLifetime.value < 600 ||
					lanIpv6dhcpPreferredLifetime.value >4294967295) { 
					alert("��Ч����ѡ����!");	
					lanIpv6dhcpPreferredLifetime.focus();
					return false;
				}
				if ( lanIpv6dhcpValidLifetime.value < 600 ||
					lanIpv6dhcpValidLifetime.value >4294967295) { 
					alert("��Ч����Ч����!");	
					lanIpv6dhcpValidLifetime.focus();
					return false;
				}
				if(Ipv6Dns1.value == "::"){
					Ipv6Dns1.value = "";
				}
				if(Ipv6Dns2.value == "::"){
					Ipv6Dns2.value = "";
				}
				if(Ipv6Dns1.value == "" && Ipv6Dns2.value == "" )  //Both DNS setting is NULL
				{
					Ipv6Dns1.focus();
					alert("IPv6��DNS ��ַ " + Ipv6Dns1.value + "\" ����Ч��IPv6 DNS ��ַ.");
					return false;
				}
				else if (Ipv6Dns1.value != "" || Ipv6Dns2.value != ""){
					if(Ipv6Dns1.value != "" ){
						if (! isUnicastIpv6Address( Ipv6Dns1.value) ){
								alert("��ѡ IPv6 DNS ��ַ\"" + Ipv6Dns1.value + "\"Ϊ��Ч��ַ�����������룡");
								Ipv6Dns1.focus();
								return false;
						}
					}
					if(Ipv6Dns2.value != "" ){
						if (! isUnicastIpv6Address( Ipv6Dns2.value) ){
								alert("���� IPv6 DNS ��ַ\"" + Ipv6Dns2.value + "\"Ϊ��Ч��ַ�����������룡");
								Ipv6Dns2.focus();
								return false;
						}
					}
				}
		}
		else if(ipv6landnsconf.value==1 || ipv6landnsconf.value==2)
		{
			if(ipv6landnsmode.value == 2)
			{
				if(Ipv6Dns1.value == "::"){
					Ipv6Dns1.value = "";
				}
				if(Ipv6Dns2.value == "::"){
					Ipv6Dns2.value = "";
				}
				else if (Ipv6Dns1.value != "" || Ipv6Dns2.value != ""){
					if(Ipv6Dns1.value != "" ){
						if (! isUnicastIpv6Address( Ipv6Dns1.value) ){
								alert("��ѡ IPv6 DNS ��ַ\"" + Ipv6Dns1.value + "\"Ϊ��Ч��ַ�����������룡");
								Ipv6Dns1.focus();
								return false;
						}
					}
					if(Ipv6Dns2.value != "" ){
						if (! isUnicastIpv6Address( Ipv6Dns2.value) ){
								alert("���� IPv6 DNS ��ַ\"" + Ipv6Dns2.value + "\"Ϊ��Ч��ַ�����������룡");
								Ipv6Dns2.focus();
								return false;
						}
					}
				}
			}
		}
		submit();
	}	
}

</script>
</head>
<!-------------------------------------------------------------------------------------->
<!--��ҳ����-->
	<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000" onLoad="on_init();">
		<blockquote>		
			<DIV align="left" style="padding-left:20px; padding-top:10px">
				<form action=/boaform/formlanipv6raconf method=POST name="lanipv6raconfform">
					<br>
					<br>
					���һ��IPv6��ַ����ѡ���������ˣ�һ�㶼��ֹʹ�������ַ�������µ����ӣ�<br>
					�������ַ�Կ��Լ��������ִ�����Ӻ��������ӣ�ֱ������Ч�����ľ�Ϊֹ��<br>
					<br>
					<br>
					<b>RA����</b><br>
					<table border="0" cellpadding="0" cellspacing="0">
						<tr>
							<td width="150">SLAAC</td>
							<td><input type='checkbox' name='enableradvd' id='enableradvd' onChange="raCheckChange()" value=<% checkWrite("radvd_enable"); %>>ʹ��</td>
						</tr>
					</table>
					<div id='div_ra' style="display:none;">
						<table border="0" cellpadding="0" cellspacing="0">
						<tr>
							<td width="150">����ģʽ</td>
							<td><select name="ipv6lanprefixmode" id='ipv6lanprefixmode' onChange="prefixModeChange()">
							<option value="1">�ֶ�����</option>
  							<option value="0">�Զ�����</option>
							</select>
							</td>
						</tr>
						</table>
						<div id='v6delegated_WANConnection' style="display:none;">
						<table border="0" cellpadding="0" cellspacing="0">
						<tr>
							<td width="150">ǰ���Դ</td>
							<td>
								<select name="ext_if" > <% if_wan_list("rtv6"); %> </select>
							</td>
						</tr>
						</table>
						</div>
						<div id="staticipv6prefix" style="display:none;">
						<table border="0" cellpadding="0" cellspacing="0">
						<tr>
								<td width="150">ǰ׺</td>
								<td><input type="text" name="Prefix" value=<% getInfo("V6prefix_ip"); %>><font color="red">*</font></td>
						</tr>
						<tr>
								<td width="150">ǰ׺����</td>
								<td><input type="text" name="Prefixlen" value=<% getInfo("V6prefix_len"); %>><font color="red">*</font>[16 - 64]</td>
						</tr>
						<tr>
								<td width="150">��ѡ����</td>
								<td><input type="text" name="ULAPrefixPreferedTime" value=<% getInfo("V6PreferredLifetime"); %>><font color="red">*</font>[600 - 4294967295 S]</td>
						</tr>
						<tr>
								<td width="150">��Ч����</td>
								<td><input type="text" name="ULAPrefixValidTime" value=<% getInfo("V6ValidLifetime"); %>><font color="red">*</font>[600 - 4294967295 S]</td>
						</tr>
						</table>
						</div>
						<table border="0" cellpadding="0" cellspacing="0">
						<tr>
							<td width="150"></td>
							<td>
								<input type='checkbox' name='AdvManagedFlagAct' id='AdvManagedFlagAct' onChange="checkChange(this)" value=<% checkWrite("lanIpv6ramanage"); %>>����Managed��־
								<input type='checkbox' name='AdvOtherConfigFlagAct' id='AdvOtherConfigFlagAct' onChange="checkChange(this)" value=<% checkWrite("lanIpv6raother"); %>>����Other��־
							</td>
						</tr>
						</table>
						<div id='staticipv6prefix2' style="display:none;">
						<table border="0" cellpadding="0" cellspacing="0">
						<tr>
								<td width="150">RA��С���</td>
								<td><input type="text" name="V6MinRtrAdvInterval" value=<% getInfo("V6MinRtrAdvInterval"); %>><font color="red">*</font>[3 - 1350 S]</td>
						</tr>
						<tr>
								<td width="150">RA�����</td>
								<td><input type="text" name="V6MaxRtrAdvInterval" value=<% getInfo("V6MaxRtrAdvInterval"); %>><font color="red">*</font>[4 - 1800 S]</td>
						</tr>
						</table>
						</div>
					</div>
					<br>
					<input type="button" class="btnsaveup" onClick="on_lanipv6raconfform_submit(0);" value="����">&nbsp; &nbsp; &nbsp; &nbsp;
					<input type="hidden" value="/net_ipv6_cmcc.asp" name="submit-url">
				</form>
			</div>
			<hr align="left" class="sep" size="1" width="90%">
			<DIV align="left" style="padding-left:20px; padding-top:10px">
				<form action=/boaform/formlanipv6dhcp method=POST name="lanipv6dhcpform">
					<b>DHCP����</b><br>
					<table border="0" cellpadding="0" cellspacing="0">
						<tr>
							<td width="150">ģʽ</td>
							<td>
								<input type="radio" name="enableDhcpServer" value=0 onClick="dhcpv6CheckChange(0)">NONE &nbsp;
								<input type="radio" name="enableDhcpServer" value=1 onClick="dhcpv6CheckChange(1)">DHCP �м� &nbsp;
								<input type="radio" name="enableDhcpServer" value=2 onClick="dhcpv6CheckChange(2)">DHCP ������ &nbsp;
							</td>
						</tr>
					</table>
					<div id='div_dhcpv6_relay' name='div_dhcpv6_relay' style="display:none;">
						<table>	
							<tr>	</tr>
							<tr>
								<td width="150">DHCP �м̰󶨵�����:</td>
								<td>
									<select name="upper_if">
										<% if_wan_list("rtv6"); %>
									</select>
								</td>
							</tr>
						</table>
					</div>
					<div id='div_dhcpv6' name='div_dhcpv6' style="display:none;">
						<table border="0" cellpadding="0" cellspacing="0">
						<tr>
							<td width="150">����ģʽ</td>
							<td><select name="ipv6landnsconf" onChange="dhcpChange()">
								<option value="0">�ֶ�����</option>
								<option value="1">�Զ�����ǰ꡺�����������</option>
								<option value="2">�Զ���������������</option>
								</select></td> 
						</tr>
						</table>
						<div id='v6dhcp_StaticMode' style="display:none;">
							<table border="0" cellpadding="0" cellspacing="0">
							<tr>
									<td width="150">�����ַ��ʽ</td>
									<td><select name="ipv6AddrFormat">
										<option value="0">��ַ�ظ�ʽ</option>
										<option value="1">EUI64��ַ��ʽ</option>
										</select></td> 
							</tr>
							<tr>
									<td width="150">ǰ׺</td>
									<td><input type="text" name="lanIpv6dhcpprefix" value=<% getInfo("dhcpv6s_prefix"); %>><font color="red">*</font></td>
							</tr>
							<tr>
									<td width="150">ǰ׺����</td>
									<td><input type="text" name="lanIpv6dhcpprefixlen" value=<% checkWrite("dhcpv6s_prefix_length"); %>><font color="red">*</font>[16 - 64]</td>
							</tr>
							<tr>
									<td width="150">��ѡ����</td>
									<td><input type="text" name="lanIpv6dhcpPreferredLifetime" value=<% getInfo("dhcpv6s_preferred_LTime"); %>><font color="red">*</font>[600 - 4294967295 S]</td>
							</tr>
							<tr>
									<td width="150">��Ч����</td>
									<td><input type="text" name="lanIpv6dhcpValidLifetime" value=<% getInfo("dhcpv6s_default_LTime"); %>><font color="red">*</font>[600 - 4294967295 S]</td>
							</tr>
							</table>
						</div>
						<div id='v6dhcp_WANConnectionMode' style="display:none;">
							<table border="0" cellpadding="0" cellspacing="0">
							<tr>
								<td width="150">������������Դ</td>
								<td><select name="ipv6landnsmode" id="ipv6landnsmode"  onChange="dnsModeChange()">
									<option value="0">HGWProxy</option>
									<option value="2">Static</option>
									<% if_wan_list("rtv6"); %>
									</select></td> 
							</tr>
							</table>
						</div>
						<div id='v6dhcp_DnsStatic' style="display:none;">
							<table border="0" cellpadding="0" cellspacing="0">
								<tr>
										<td width="150px">��ѡDNS������</td>
										<td><input type="text" name="Ipv6Dns1" size="36" maxlength="39" value=<% getInfo("wan-dnsv61"); %>><font color="red">*</font></td>
								</tr>
								<tr>
										<td width="150px">����DNS������</td>
										<td><input type=text name="Ipv6Dns2" size="36" maxlength="39" value=<% getInfo("wan-dnsv62"); %>></td>
								</tr>
							</table>
						</div>
					</div>
					<br>
					<input type="button" class="btnsaveup" onClick="on_lanipv6dhcpform_submit(0);" value="����">&nbsp; &nbsp; &nbsp; &nbsp;
					<input type="hidden" value="/net_ipv6_cmcc.asp" name="submit-url">
				</form>
			</div>
		</blockquote>
		
		
<script>
	modeIndex = <% checkWrite("enableDhcpv6Server"); %>;
	document.lanipv6dhcpform.enableDhcpServer[modeIndex].checked = true;
	
	raCheckChange();
	dhcpv6CheckChange(modeIndex);
	
	ifIdx = <% getInfo("prefix-delegation-wan-conn"); %>;
	if (ifIdx != 65535)
		document.lanipv6raconfform.ext_if.value = ifIdx;
	else
		document.lanipv6raconfform.ext_if.selectedIndex = 0;

	document.lanipv6raconfform.ipv6lanprefixmode.value = <% getInfo("prefix-mode"); %>;
	prefixModeChange();
	
	document.lanipv6dhcpform.ipv6landnsconf.value=<% getInfo("dhcpv6s_dnsassignmode"); %>;
	document.lanipv6dhcpform.ipv6AddrFormat.value=<% getInfo("dhcpv6s_pooladdrformat"); %>;
	document.lanipv6dhcpform.ipv6landnsmode.value=<% getInfo("dnsv6-mode"); %>;
	
	dhcpChange();
</script>
	</body>
</html>
