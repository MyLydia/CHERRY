<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<!--系统默认模板-->
<HTML>
<HEAD>
<TITLE>中国电信</TITLE>
<META http-equiv=pragma content=no-cache>
<META http-equiv=cache-control content="no-cache, must-revalidate">
<META http-equiv=content-type content="text/html; charset=gbk">
<META http-equiv=content-script-type content=text/javascript>
<!--系统公共css-->
<STYLE type=text/css>
@import url(/style/default.css);
</STYLE>
<!--系统公共脚本-->
<SCRIPT language="javascript" src="/common.js"></SCRIPT>
<script type="text/javascript" src="/base64_code.js"></script>
<SCRIPT language="javascript" type="text/javascript">
var loginFlag = 0;

if (window.top != window.self) {
// in a frame
	window.top.location.href = "/admin/login.asp";
} 

function myKeyDown(e) 
{
	var code;

	if (!e) {
		e = window.event;
	}

	if (e.keyCode) {
		code = e.keyCode;
	} else if (e.which) {
		code = e.which;
	}

	if (code == 13) {
		on_submit();
	}

	return true;
}

document.onkeydown = myKeyDown;
if (document.captureEvents) document.captureEvents(Event.KEYDOWN);

/********************************************************************
**          on document load
********************************************************************/
function on_init()
{
	document.forms[0].username1.focus();

	if(document.referrer.search("usereg.asp") != -1)
		return ;

	<% checkPopupRegPage(); %>
}

/********************************************************************
**          on document submit
********************************************************************/
function on_submit() 
{
	if (loginFlag)
		return 1;
	
	with ( document.forms[0] ) {
		if(document.getElementById("ah_login").style.display=="")
		{
			username.value = username2.value;
			psd.value = psd2.value;
		}
		else
		{
			username.value = username1.value;
			psd.value = psd1.value;
		}
		if(username.value.length <= 0) {
			alert("用户名为空，请输入用户名!");
			return;
		}
		if(psd.value.length <= 0) {
			alert("密码为空，请输入密码!");
			return;
		}
		//setpass();
		psd.value = encode64(psd.value);
		username1.disabled = true;
		username2.disabled = true;
		psd1.disabled = true;
		psd2.disabled = true;
		//alert("psd.value " + psd.value);
		loginFlag = 1;
			
		postTableEncrypt(document.forms[0].postSecurityFlag, document.cmlogin);
		
		submit();
	}
}

function on_Diag()
{
	window.location.href="/diag_index.html";
}
</SCRIPT>

</head>

<body leftmargin="0" topmargin="0"  bgcolor="white" onLoad="on_init();">
<form action=/boaform/admin/formLogin method=POST name="cmlogin">
<div id="ah_login" width="100%" height="100%" align="center" valign="middle" <% checkWrite("ah_login"); %>>
	<div style="background-image:url(/image/bg_ah_login_01.gif); width:100%; height:544px; float:center">
		<div style="background-image:url(/image/bg_ah_login.gif); width:830px; height:544px; float:center">
			<div style="width:830px; height:260px; float:center">
			</div>
			<div style="width:830px; float:center">
			<table style="width:830px;" align="center">
				<tr>
					<td align="right" width="45%" height="35px"><font size="2">用户名：</font></td>
					<td ><input type="text" name="username2" id="username2" style="width:150; height:25" value="<% getInfo("normal-user"); %>"/></td>
				</tr>
				<tr>
					<td  align="right" width="45%" height="35px"><font size="2">密码：</font></td>
					<td ><input type="password" name="psd2" id="psd2" autocomplete="off" style="width:150; height:25"/></td>
				</tr>
				<tr>
					<td colspan="2" align="center" height="35px">
						<div <% checkWrite("dev_reg_btn1"); %> >
						<input type="button" style="width:70px;" onClick="on_submit();" value="登录"/>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
						<input type="button" name="reg" style="width:70px; display:inline" value="设备注册" onclick="location.href='/usereg.asp';">
						</div>
						<div <% checkWrite("dev_reg_btn2"); %> >
						<input type="button" style="width:70px;" onClick="on_submit();" value="登录"/>
						</div>
					</td>
				</tr>
				<tr>
					<td colspan="2" align="center" height="35px"><font size="2" color="#E60012">非电信维护人员，请勿操作‘设备注册’按钮，否则易导致故障</font></td>
				</tr>
			</table>
			</div>
			<!---
			<div style="width:830px; height:200px; float:center">
			</div>
			--->
		</div>
	</div>
</div>
<table id="login" width="100%" height="100%" align="center" valign="middle" <% checkWrite("login"); %>>
<tr>
	<td width="25%" height="25%"></td>
	<td width="50%" ></td>
	<td width="25%"></td>
</tr>
<tr  align="left" valign="top">
	<td height="50%"></td>
	<td>
		<table width="100%" cellspacing="0"  style="font-size:10pt">
			<tr bgcolor="#427594" height="10%">
				<td  bgcolor="#427594" width="1"></td>
				<td>&nbsp;&nbsp;<font color="white">用户登录</font></td>
				<td  bgcolor="#427594" width="1"></td>
			</tr>
			<tr  align="center" valign="middle" >
				<td  bgcolor="#427594" width="1"></td>
				<td><table  cellspacing="8"  style="font-size:10pt">
					<tr align="center" valign="middle">
						<td colspan="3"><IMG height="78" src="/image/logo.gif" width="225" border=0></td>
					</tr>
					<tr><td width="21">&nbsp;&nbsp;&nbsp;</td><td>用户:</td><td><input type="text" name="username1" id="username1" style="width:150;" value="<% getInfo("normal-user"); %>"/></td></tr>
					<tr><td width="21">&nbsp;&nbsp;&nbsp;</td><td>密码:</td><td><input type="password" name="psd1" id="psd1" autocomplete="off" style="width:150;"/></td></tr>
				</table></td>
				<td  bgcolor="#427594" width="1"></td>
			</tr>
			<tr bgcolor="#427594" height="10%"  align="center" valign="middle" >
				<td  bgcolor="#427594" width="1"></td>
				<td>&nbsp;&nbsp;<input type="button" class="button" onClick="on_submit();" value="登录"/>
				&nbsp;&nbsp;<input type="reset" value="重写" />&nbsp;&nbsp;<!--<input type="button" value="快速诊断" onClick="on_Diag();" />&nbsp;&nbsp;-->
				<input type="hidden" name="csrfmiddlewaretoken" value="KbyUmhTLMpYj7CD2di7JKP1P3qmLlkPt" />
				</td>
				<td  bgcolor="#427594" width="1"></td>
			</tr>
		</table>
	</td>
	<td></td>
</tr>
<tr>
	<td height="25%"></td>
	<td></td>
	<td></td>
</tr>
</table>
<input type="hidden" name="username" id="username" value=''>
<input type="hidden" name="psd" id="psd" value=''>
<input type="hidden" name="postSecurityFlag" value="">
</form>
</BODY>
<%addHttpNoCache();%>
</html>
