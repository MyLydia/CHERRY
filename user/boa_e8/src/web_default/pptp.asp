<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<html>
<head>
<TITLE>PPTP配置</TITLE>
<meta http-equiv=pragma content=no-cache>
<meta http-equiv=cache-control content="no-cache, must-revalidate">
<meta http-equiv=content-type content="text/html; charset=utf-8">
<meta http-equiv=content-script-type content=text/javascript>
<style type=text/css>
@import url(/style/default.css);
</style>
<script language="javascript" src="common.js"></script>
<SCRIPT language="javascript" type="text/javascript">
function checkTextStr(str)
{
	for (var i=0; i<str.length; i++) 
	{
		if ( str.charAt(i) == '%' || str.charAt(i) =='&' ||str.charAt(i) =='\\' || str.charAt(i) =='?' || str.charAt(i)=='"') 
			return false;			
	}
	return true;
}

function pptpSelection()
{
	if (document.pptp.pptpen[0].checked) {
		document.pptp.server.disabled = true;
		document.pptp.username.disabled = true;
		document.pptp.pValue.disabled = true;
		document.pptp.auth.disabled = true;
		document.pptp.defaultgw.disabled = true;
		document.pptp.addPPtP.disabled = true;
		document.pptp.enctype.disabled = true;
	}
	else {
		document.pptp.server.disabled = false;
		document.pptp.username.disabled = false;
		document.pptp.pValue.disabled = false;
		document.pptp.auth.disabled = false;
		document.pptp.defaultgw.disabled = false;
		document.pptp.addPPtP.disabled = false;
		document.pptp.enctype.disabled = true;
	}
}


function encryClick()
{
	if (document.pptp.auth.value==3) {
		document.pptp.enctype.disabled = false;
	}else
		document.pptp.enctype.disabled = true;
}

function onClickPPtpEnable()
{
	pptpSelection();
	document.pptp.lst.value = "enable";
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	document.pptp.submit();
}

function addPPtPItf(obj)
{
	if(document.pptp.pptpen[0].checked)
		return false;
	
	if (document.pptp.server.value=="") {
		alert("请输入正确的pptp服务器IP地址");
		document.pptp.server.focus();
		return false;
	}
	
	if(!checkTextStr(document.pptp.server.value))
	{
		alert("不正确的服务器IP地址");
		document.pptp.server.focus();
		return false;		
	}
	
	if (document.pptp.username.value=="")
	{
		alert("请输入正确的pptp拨号用户名");
		document.pptp.username.focus();
		return false;
	}
	if(!checkTextStr(document.pptp.username.value))
	{
		alert("不正确的拨号用户名");
		document.pptp.username.focus();
		return false;		
	}
	if (document.pptp.pValue.value=="") {
		alert("请输入正确的拨号密码");
		document.pptp.pValue.focus();
		return false;
	}
	if(!checkTextStr(document.pptp.pValue.value))
	{
		alert("不正确的拨号密码");
		document.pptp.pValue.focus();
		return false;		
	}
	obj.isclick = 1;

	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	
	return true;
}

function deleteOneEntry(obj)
{
	if ( !confirm('删除这项设定?') ) {
		return false;
	}
	else
	{
		obj.isclick = 1;
		postTableEncrypt(document.pptp.postSecurityFlag, document.pptp);
		return true;
	}
}

function on_submit(obj)
{
	obj.isclick = 1;
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	return true;
}

</SCRIPT>
</head>

<body>
<blockquote>
<form action=/boaform/formPPtP method=POST name="pptp">
<table border=0 width="500" cellspacing=0 cellpadding=0>
  <tr><hr size=1 noshade align=top></tr>
  <tr>
      <td width="30%"><font size=2><b>PPTP VPN:</b></td>
      <td width="70%"><font size=2>
      	<input type="radio" value=0 name="pptpen" <% checkWrite("pptpenable0"); %> onClick="onClickPPtpEnable()">禁用&nbsp;&nbsp;
     	<input type="radio" value=1 name="pptpen" <% checkWrite("pptpenable1"); %> onClick="onClickPPtpEnable()">启用
      </td>
  </tr>
</table>
<input type="hidden" id="lst" name="lst" value="">
<br>

<table border=0 width="500" cellspacing=0 cellpadding=0>
  <tr>
    <td width="30%"><font size=2><b>服务器IP地址:</b></td>
    <td width="70%"><input type="text" name="server" size="32" maxlength="256"></td>
  </tr>
  <tr>
    <td width="30%"><font size=2></b>拨号用户名:</b></td>
    <td width="70%"><input type="text" name="username" size="15" maxlength="35"></td>
  </tr>
  <tr>
    <td width="30%"><font size=2></b>拨号密码:</b></td>
    <td width="70%"><input type="text" name="pValue" size="15" maxlength="35"></td>
  </tr>
  <tr>
    <td width="30%"><font size=2></b>验证协议:</b></td>
    <td width="70%"><select name="auth" onClick="encryClick()">
      <option value="0">自动</option>
      <option value="1">PAP</option>
      <option value="2">CHAP</option>
      <option value="3">CHAPMSV2</option>
      </select>
    </td>
  </tr>
  <tr>
    <td width="30%"><font size=2></b>加密:</b></td>
    <td width="70%"><select name="enctype" >
      <option value="0">无</option>
      <option value="1">MPPE</option>
      <option value="2">MPPC</option>
      <option value="3">MPPE&MPPC</option>
      </select>
    </td>
  </tr>
  <tr>
    <td width="30%"><font size=2><b>设定为缺省网关:</b></td>
    <td width="70%"><input type="checkbox" name="defaultgw"></td>
  </tr>
</table>

<table border=0 width="500" cellspacing=0 cellpadding=0>
  </tr>
      <td><input type="submit" value="保存/应用" name="addPPtP" onClick="return addPPtPItf(this)">&nbsp;&nbsp;</td>
  </tr>
</table>
<br><br>

<table border=0 width="600" cellspacing=4 cellpadding=0>
  <tr><font size=2><b>PPTP 通道配置表 (配置来源: WUI):</b></font></tr>
  <tr>
    <td align=center width="3%" bgcolor="#808080"><font size=2>选择</font></td>
    <td align=center width="5%" bgcolor="#808080"><font size=2>服务接口</font></td>
    <td align=center width="5%" bgcolor="#808080"><font size=2>服务器IP地址</font></td>
    <td align=center width="8%" bgcolor="#808080"><font size=2>连接状态</font></td>
  </tr>
	<% pptpWuiList(); %>
</table>
<table border=0 width="900" cellspacing=4 cellpadding=0>
  <tr><font size=2><b>PPTP 通道配置表 (配置来源: Gdbus):</b></font></tr>
  <tr>
    <td align=center width="3%" bgcolor="#808080"><font size=2>选择</font></td>
    <td align=center width="5%" bgcolor="#808080"><font size=2>服务接口</font></td>
    <td align=center width="5%" bgcolor="#808080"><font size=2>服务器IP地址</font></td>
    <td align=center width="5%" bgcolor="#808080"><font size=2>通道验证协议</font></td>
    <td align=center width="5%" bgcolor="#808080"><font size=2>PPP验证协议</font></td>
	<td align=center width="5%" bgcolor="#808080"><font size=2>帐密模式</font></td>
	<td align=center width="5%" bgcolor="#808080"><font size=2>优先权</font></td>
	<td align=center width="5%" bgcolor="#808080"><font size=2>閒置时间</font></td>
	<td align=center width="5%" bgcolor="#808080"><font size=2>关联模式</font></td>
    <td align=center width="8%" bgcolor="#808080"><font size=2>连接状态</font></td>
  </tr>
	<% pptpGdbusList(); %>
</table>
<table border=0 width="900" cellspacing=4 cellpadding=0>
  <tr>
    <td align=center width="5%" bgcolor="#808080"><font size=2>服务接口</font></td>
    <td align=center width="30%" bgcolor="#808080"><font size=2>关联条件</font></td>
  </tr>
	<% pptpGdbusAttachList(); %>
</table>
<br>
<input type="submit" value="删除" name="delSel" onClick="return deleteOneEntry(this)">&nbsp;&nbsp;
<input type="hidden" value="/pptp.asp" name="submit-url">
<input type="hidden" name="postSecurityFlag" value="">
<script>
	pptpSelection();
</script>
</form>
</blockquote>
</body>
</html>
