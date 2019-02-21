<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<!--系统默认模板-->
<HTML>
<HEAD>
<TITLE>Fast BSS Transition (802.11r)</TITLE>
<META http-equiv=pragma content=no-cache>
<META http-equiv=cache-control content="no-cache, must-revalidate">
<META http-equiv=content-type content="text/html; charset=gbk">
<META http-equiv=content-script-type content=text/javascript>
<!--系统公共css-->
<STYLE type=text/css>
@import url(/style/default.css);
</STYLE>
<!--系统公共脚本-->
<SCRIPT language="javascript" src="urlEncodeGBK.js"></SCRIPT>
<SCRIPT language="javascript" src="common.js"></SCRIPT>
<script type="text/javascript" src="share.js" charset="gbk"></script>
<SCRIPT language="javascript" type="text/javascript">

var ssid_num;
var ssidIdx = <% checkWrite("wlan_idx"); %>;
var _dotIEEE80211r=new Array();
var _encrypt=new Array();
var _ft_enable=new Array();
var _ft_mdid=new Array();
var _ft_over_ds=new Array();
var _ft_res_request=new Array();
var _ft_r0key_timeout=new Array();
var _ft_reasoc_timeout=new Array();
var _ft_r0kh_id=new Array();
var _ft_push=new Array();
var _ft_kh_num=new Array();

function SSIDSelected(index, form)
{
	if (ssid_num == 0)
		return;

	if(ssidIdx==0){
		document.formFt.ftSSID.options[0] = new Option("SSID1", "0", false, false);
		document.formFtKhAdd.ftSSID.options[0] = new Option("SSID1", "0", false, false);
	}
	else{
		document.formFt.ftSSID.options[0] = new Option("SSID5", "0", false, false);
		document.formFtKhAdd.ftSSID.options[0] = new Option("SSID5", "0", false, false);
	}

	document.formFt.ftSSID.value = form.ftSSID.value;
	document.formFtKhAdd.ftSSID.value = form.ftSSID.value;
	document.formFtKhDel.ftSSID.value = form.ftSSID.value;

	document.formFt.security_method.value = _encrypt[index];
	if ((_encrypt[index]==4) || (_encrypt[index]==6)) { //WPA2,WPA2-MIXED
		_dotIEEE80211r[index] = true;
		enableRadioGroup(document.formFt.ft_enable);
	} else { //NONE,WEP
		_dotIEEE80211r[index] = false;
		disableRadioGroup(document.formFt.ft_enable);
	}

	enable_80211r_setting(index);
	load_80211r_setting(index);
}

function enable_80211r_setting(index)
{
	if ((_dotIEEE80211r[index]==false) || (document.formFt.ft_enable[0].checked==true)) {
		document.formFt.ft_mdid.disabled = true;
		disableRadioGroup(document.formFt.ft_over_ds);
		disableRadioGroup(document.formFt.ft_res_request);
		document.formFt.ft_r0key_timeout.disabled = true;
		document.formFt.ft_reasoc_timeout.disabled = true;
		document.formFt.ft_r0kh_id.disabled = true;
		disableRadioGroup(document.formFt.ft_push);
	} else {
		document.formFt.ft_mdid.disabled = false;
		enableRadioGroup(document.formFt.ft_over_ds);
		enableRadioGroup(document.formFt.ft_res_request);
		document.formFt.ft_r0key_timeout.disabled = false;
		document.formFt.ft_reasoc_timeout.disabled = false;
		document.formFt.ft_r0kh_id.disabled = false;
		enableRadioGroup(document.formFt.ft_push);
	}
}

function load_80211r_setting(index)
{
	document.formFt.ft_enable[_ft_enable[index]].checked = true;
	document.formFt.ft_mdid.value = _ft_mdid[index];
	document.formFt.ft_over_ds[_ft_over_ds[index]].checked = true;
	document.formFt.ft_res_request[_ft_res_request[index]].checked = true;
	document.formFt.ft_r0key_timeout.value = _ft_r0key_timeout[index];
	document.formFt.ft_reasoc_timeout.value = _ft_reasoc_timeout[index];
	document.formFt.ft_r0kh_id.value = _ft_r0kh_id[index];
	document.formFt.ft_push[_ft_push[index]].checked = true;
	enable_80211r_setting(index);
}

function check_80211r_setting()
{
	var i, len, val;
	
	//check MDID
	len = document.formFt.ft_mdid.value.length;
	if (len != 4) {
		alert("无效的 MDID (2 个八位字节标识符作为十六进制字符串)");
		document.formFt.ft_mdid.focus();
		return false;
	}
	for (i=0; i<len; i++) {
		if (is_hex(document.formFt.ft_mdid.value.charAt(i)) == false) {
			alert("无效的十六进制数字");
			document.formFt.ft_mdid.focus();
			return false;
		}
	}
	
	//check Key expiration timeout
	val = parseInt(document.formFt.ft_r0key_timeout.value);
	if (val>65535)
	{
		alert("key expiration timeout范围无效 (0 或 1 ~ 65535 分钟)");
		document.formFt.ft_r0key_timeout.focus();
		return false;
	}
	
	// check Reassociation timeout
	val = parseInt(document.formFt.ft_reasoc_timeout.value);
	if ((val!=0) && (val<1000 || val>65535))
	{
		alert("reassociation timeout 无效(0 或 1000 ~ 65535)");
		document.formFt.ft_reasoc_timeout.focus();
		return false;
	}
	
	// check NAS identifier
	len = document.formFt.ft_r0kh_id.value.length;
	if (len<1 || len>48)
	{
		alert("无效的 NAS 标识符 (1 ~ 48 个字符)");
		document.formFt.ft_r0kh_id.focus();
		return false;
	}
	document.formFtKhAdd.ftSaveConfig.isclick = 1;
	postTableEncrypt(document.formFt.postSecurityFlag, document.formFt);
	
	return true;
}

function is_hex(ch)
{
	if ((ch>='0' && ch<='9') || (ch>='a' && ch<='f') || (ch>='A' && ch<='F'))
		return true;
	else
		return false;
}

function check_kh_setting(index)
{
	var len;
	
	// check if exceed max number of KH entry
	if (_ft_kh_num[index] >= <% checkWrite("11r_ftkh_num") %>) {
		alert("超过最大值。");
		return false;
	}
	
	// check MAC address
	if (!checkMac(document.formFtKhAdd.kh_mac, 1))
		return false;

	// check NAS ID (1~48 characters)
	len = document.formFtKhAdd.kh_nas_id.value.length;
	if (len<1 || len>48)
	{
		alert("无效的 NAS 标识符 (1 ~ 48 个字符)");
		document.formFtKhAdd.kh_nas_id.focus();
		return false;
	}
	for (i=0; i<len; i++) {
		if (document.formFtKhAdd.kh_nas_id.value.charAt(i) == ' ') {
			alert("在 NAS 标识符字段中不允许有White-space。");
			document.formFtKhAdd.kh_nas_id.focus();
			return false;
		}
	}

	// check AES wrap/unwrap key (16 octets)
	len = document.formFtKhAdd.kh_kek.value.length;
	if (len<1 || len>32)
	{
		alert("无效的密钥长度 (应该是 16 个八位字节或 1 ~ 32 个字符)");
		document.formFtKhAdd.kh_nas_id.focus();
		return false;
	}
	document.formFtKhAdd.ftAddKH.isclick = 1;
	postTableEncrypt(document.formFtKhAdd.postSecurityFlag, document.formFtKhAdd);
	
	return true;
}

function deleteOneEntry(obj)
{
	obj.isclick = 1;
	postTableEncrypt(document.formFtKhDel.postSecurityFlag, document.formFtKhDel);
	
	if ( !confirm('删除这项设定?') ) {
		return false;
	}
	else
		return true;
}
        
function deleteAllEntry(obj)
{
	obj.isclick = 1;
	postTableEncrypt(document.formFtKhDel.postSecurityFlag, document.formFtKhDel);
	
	if ( !confirm('删除本表所有设定?') ) {
		return false;
	}
	else
		return true;
}

</script>
</head>

<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000" onload="SSIDSelected(0, formFt);">
<blockquote>
<DIV align="left" style="padding-left:20px; padding-top:10px">
<b>Fast BSS Transition (802.11r)</b><br>

<!-- Page description -->
<table border=0 width="500" cellspacing=4 cellpadding=0>
	<tr>
		<td>
		此页面允许您更改设置 Fast BSS Transition (802.11r)
		</td>
	</tr>
	<tr><td><hr size=1 noshade align=top></td></tr>
</table>

<div id="wlan_dot11r_table" style="display:none">
<!-- 802.11r driver configuration -->
<form action=/boaform/formFt method=POST name="formFt">
<!-- select SSID -->
<table border=0 width="500" cellspacing=4 cellpadding=0>
		<tr>
			<td width="35%">SSID:</td>
			<td width="65%">
				<font size="2">
				<select name=ftSSID onChange="SSIDSelected( this.selectedIndex, this.form )"><% SSID_select(); %></select>
				</font>
			</td>
		</tr>
		<tr>
			<td width="35%">认证方式:</td>
			<td width="65%">
				<font size="2">
				<select size="1" id="security_method" name="security_method" disabled>
					<option value=0>None</option>
					<option value=1>WEP</option>
					<option value=2>WPA</option>
					<option value=4>WPA2</option>
					<option value=6>WPA2 Mixed</option>
				</select>
				</font>
			</td>
		</tr>
</table>

<!-- ----------------------------------------------------- -->
<table border=0 width="500" cellspacing=4 cellpadding=0>
	<tr><td><hr size=1 noshade align=top></td></tr>
</table>

<!-- mib settings -->
<table border=0 width="500" cellspacing=4 cellpadding=0>
	<!-- Enable/Disable Fast BSS Transition -->
	<tr id="show_ft_enable">
		<td width="30%">
			IEEE 802.11r:
		</td>
		<td width="70%">
			<font size="2">
			<input type="radio" name="ft_enable" value=0 onClick="enable_80211r_setting()" >Disable
			<input type="radio" name="ft_enable" value=1 onClick="enable_80211r_setting()" >Enable
			</font>
		</td>
	</tr>

	<!-- Mobility Domain ID -->
	<tr id="show_ft_mdid">
		<td width="30%">
			Mobility Domain ID:
		</td>
		<td width="70%" class="bggrey">
			<input type="text" name="ft_mdid" size="4" maxlength="4" value="A1B2">
		</td>
	</tr>

	<!-- Support over DS -->
	<tr id="show_ft_over_ds">
		<td width="30%">
			Support over DS:
		</td>
		<td width="70%">
			<font size="2">
			<input type="radio" name="ft_over_ds" value=0 >Disable
			<input type="radio" name="ft_over_ds" value=1 >Enable
			</font>
		</td>
	</tr>

	<!-- Support resource request -->
	<tr id="show_ft_res_request" style="display:none">
		<td width="30%">
			Support resource request:
		</td>
		<td width="70%">
			<font size="2">
			<input type="radio" name="ft_res_request" value=0 >Disable
			<input type="radio" name="ft_res_request" value=1 >Enable
			</font>
		</td>
	</tr>

	<!-- Key expiration timeout -->
	<tr id="show_ft_r0key_timeout">
		<td width="30%">
			Key expiration timeout:
		</td>
		<td width="70%">
			<input type="text" name="ft_r0key_timeout" size="12" maxlength="10" value="10000">
			&nbsp;(1..65535 minutes, 0:disable)
		</td>
	</tr>

	<!-- Reassociation timeout -->
	<tr id="show_ft_reasoc_timeout">
		<td width="30%">
			Reassociation timeout:
		</td>
		<td width="70%">
			<input type="text" name="ft_reasoc_timeout" size="12" maxlength="10" value="1000">
			&nbsp;(1000..65535 seconds, 0:disable)
		</td>
	</tr>

	<!-- NAS identifier (R0KH-ID) -->
	<tr id="show_ft_r0kh_id">
		<td width="30%">
			NAS identifier:
		</td>
		<td width="70%" class="bggrey">
			<input type="text" name="ft_r0kh_id" size="30" maxlength="48" value="www.realtek.com.tw">
			&nbsp;(1~48 characters)
		</td>
	</tr>

	<!-- Enable Key-Push, this is for FT-Daemon -->
	<tr id="show_ft_push">
		<td width="30%" class="bgblue">
			Support Key-Push:
		</td>
		<td width="70%" class="bggrey">
			<input type="radio" name="ft_push" value=0 >Disable
			<input type="radio" name="ft_push" value=1 >Enable
		</td>
	</tr>

	<tr>
		<td width="100%" colspan="2" height="40">
			<input type="hidden" name="wlan_idx" value=<% checkWrite("wlan_idx"); %>>
			<input type="hidden" name="submit-url" value="/net_wlan_ft.asp">
			<input type="submit" name="ftSaveConfig" value="保存/应用" onclick="return check_80211r_setting()">
			<input name="button" type='button' onClick ='history.back()' value='后退'>
			<input type="hidden" name="postSecurityFlag" value="">
		</td>
	</tr>
</table>
</form>

<!-- ----------------------------------------------------- -->
<table border=0 width="500" cellspacing=4 cellpadding=0>
	<tr><td><hr size=1 noshade align=top></td></tr>
</table>

<!-- Add R0KH/R1KH entry -->
<form action=/boaform/formFt method=POST name="formFtKhAdd">
<table border=0 width="500" cellspacing=4 cellpadding=0>
	<tr>
		<td colspan="2">Key Holder 配置:</td>
	</tr>

	<tr>
		<td width="35%">SSID:</td>
		<td width="65%">
			<select name=ftSSID onChange="SSIDSelected( this.selectedIndex, this.form )"><% SSID_select(); %></select>
		</td>
	</tr>
</table>

<table>
	<tr>
		<td width="25%">MAC地址:</td>
		<td width="75%"><input type="text" name="kh_mac" size="10" maxlength="12" value="">
			&nbsp(ex: 00E086710502)</td>
	</tr>

	<tr>
		<td width="25%">NAS identifier:</td>
		<td width="75%" nowrap><input type="text" name="kh_nas_id" size="34" maxlength="48" value="">
			&nbsp(1~48 characters)</td>
	</tr>

	<tr>
		<td width="25%">加密金钥:</td>
		<td width="75%" nowrap><input type="text" name="kh_kek" size="34" maxlength="32" value="">
			&nbsp;(16 octets or passphrase)</td>
	</tr>

	<tr>
		<td width="100%" colspan="2" height="40">
		<input type="hidden" name="submit-url" value="/net_wlan_ft.asp">
		<input type="hidden" name="wlan_idx" value=<% checkWrite("wlan_idx"); %>>
		<input type="submit" name="ftAddKH" value="新增"
			onClick="return check_kh_setting(ftSSID.selectedIndex)">&nbsp;&nbsp;
		<input type="reset" name="reset" value="重置">&nbsp;&nbsp;
		<input type="hidden" name="postSecurityFlag" value="">
		</td>
	</tr>
</table>
</form>

<!-- ----------------------------------------------------- -->
<table border=0 width="500" cellspacing=4 cellpadding=0>
	<tr><td><hr size=1 noshade align=top></td></tr>
</table>

<!-- Delete R0KH/R1KH entry -->
<form action=/boaform/formFt method=POST name="formFtKhDel">
<table class="flat" border=0 cellpadding=2 cellspacing=0 width="700">
	<tr>
		<td colspan="4">Current Key Holder 资讯:</td>
	</tr>
	<% wlFtKhList(); %>

	<tr>
		<td width="100%" colspan="4" height="40">
		<input type="hidden" name="submit-url" value="/net_wlan_ft.asp">
		<input type="hidden" name="wlan_idx" value=<% checkWrite("wlan_idx"); %>>
		<input type="hidden" name=ftSSID>
		<input type="submit" name="ftDelSelKh" value="删除所选"
			onClick="return deleteOneEntry(this)">&nbsp;&nbsp;
		<input type="submit" name="ftDelAllKh" value="全部删除"
			onClick="return deleteAllEntry(this)">&nbsp;&nbsp;
		<input type="hidden" name="postSecurityFlag" value="">
		</td>
	</tr>
</table>
</form>
</div>

<script>
<% initPage("wlft"); %>
</script>
</DIV>
</blockquote>
</body>
</html>
