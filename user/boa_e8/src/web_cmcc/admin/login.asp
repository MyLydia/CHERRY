<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<!--系统默认模板-->
<HTML>
<HEAD>
<TITLE>中国移动</TITLE>
<META http-equiv=pragma content=no-cache>
<META http-equiv=cache-control content="no-cache, must-revalidate">
<META http-equiv=content-type content="text/html; charset=gbk">
<META http-equiv=content-script-type content=text/javascript>
<!--系统公共脚本-->
<link rel="stylesheet" type="text/css" href="/style/backgroup_style.css">
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
		loginFlag = 1;
		
		submit();
	}
}

function on_Diag()
{
	window.location.href="/diag_index.html";
}
</SCRIPT>
<style>
body,input,td, p, span{
	font-family: "微软雅黑";
}
body{
	background:#EFF1EE;
}
.login_logo{
	width:246px;
	height:30px;
	padding-left:10px;
}
.login_txt1{
	height:180px;
}
.login_txt2{
	height:40px;
	text-align:40px;
	color: white;
	font-size: 16px;
	margin-left: 30px;
}
.tex_inpt input{
	height: 30px;
	width: 350px;
	border-radius: 5px;
	border: solid 1px #e9e9e9;
	outline: none;
	font-size: 15px;
	padding-left: 10px;
}
.version{
	height: 80px;
	text-align:center;
	line-height:80px;
	font-size:14px;
	color:#51535A
}
.login_title span {
    position: absolute;
    top: 13px;
    left: 190px;
	color:#fff;
}
.main_div{
	margin: 0 auto;
	text-align:center;
	width: 600px;
	position: relative;
	min-height: 300px;
	-moz-border-radius-topleft: 10px;
	-moz-border-radius-topright: 10px;
	-moz-border-radius-bottomright: 10px;
	-moz-border-radius-bottomleft: 10px;
	-webkit-border-top-left-radius: 10px;
	-webkit-border-top-right-radius: 10px;
	-webkit-border-bottom-right-radius: 10px;
	-webkit-border-bottom-left-radius: 10px;
	border-top-left-radius: 10px;
	border-top-right-radius: 10px;
	border-bottom-right-radius: 10px;
	border-bottom-left-radius: 10px;
	background:#fff;
}
.top_bar{
	-moz-border-radius-topleft: 10px;
	-moz-border-radius-topright: 10px;
	-moz-border-radius-bottomright: 0px;
	-moz-border-radius-bottomleft: 0px;
	-webkit-border-top-left-radius: 10px;
	-webkit-border-top-right-radius: 10px;
	-webkit-border-bottom-right-radius: 0px;
	-webkit-border-bottom-left-radius: 0px;
	border-top-left-radius: 10px;
	border-top-right-radius: 10px;
	border-bottom-right-radius: 0px;
	border-bottom-left-radius: 0px;
	background:#363e47;
	width:600px;
	height:40px;
	margin: 0 auto;
	margin-top: 50px;
}
.msg_tex{
    padding-top: 50px;
    font-size: 18px;
	display: inline-block;
}
.msg_btn input{
	margin:5px;
}
</style>

</head>

<body leftmargin="0" topmargin="0"  bgcolor="white" onLoad="on_init();">
<form action=/boaform/admin/formLogin method=POST name="cmlogin">
<div id="ah_login" <% checkWrite("ah_login"); %> >
<div class="top_bar"></div>
<div class="main_div">
			
			<table  class="msg_tex" style="width:600px;" align="center">
				<tr>
					<td width="250" align="right" height="35px"><font size="2">用户名：</font></td>
					<td width="350"><input type="text" name="username2" id="username2" style="width:150; height:25" value="<% getInfo("normal-user"); %>"/></td>
				</tr>
				<tr>
					<td  align="right" height="35px"><font size="2">密码：</font></td>
					<td ><input type="password" name="psd2" id="psd2" style="width:150; height:25"/></td>
				</tr>
				<tr>
					<td colspan="2" align="center" height="35px" width="100%">
						<div <% checkWrite("dev_reg_btn1"); %> >
						<input class="reset_btn" type="button" onClick="on_submit();" value="登录"/>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
						<input class="reset_btn" type="button" name="reg" value="设备注册" onclick="location.href='/usereg.asp';">
						</div>
						<div <% checkWrite("dev_reg_btn2"); %> >
						<input class="reset_btn" type="button" onClick="on_submit();" value="登录"/>
						</div>
					</td>
				</tr>
				<tr>
					<td colspan="2" align="center" height="35px"><font size="2" color="#E60012">非专业维护人员，请勿操作‘设备注册’按钮，否则易导致故障</font></td>
				</tr>
			</table>
	

	</div>
</div>
<br><br><br><br>
<table class="type_backgroup" id="login" width="400" height="430" align="center" valign="middle" <% checkWrite("login"); %>>

<tr  align="left" valign="top">
	<td>
		<table cellspacing="0"  style="font-size:10pt" width="400" height="430" >
			<tr height="40" class="login_title">
				<td class="login_title">
				<img class="login_logo type_cmcc" src="/image/mobile2.png"><!--<span> 型号: CMCC</span>-->
				</td>
							<!--<td  bgcolor="#427594" width="1"></td>  -->
			</tr>
			<tr><td>&nbsp;</td></tr>
			<tr  align="center" valign="middle">
				<td align="center"><img src="/image/qrcode.png" height="120" width="107"></td>
			</tr>
			<tr  align="center" valign="middle" height="20">
				<td class="login_txt2" align="center">手机客户端</td>
			</tr>
			<tr  align="center" valign="middle" >
				<td>
				<table>
						<tr>
							<td colspan="2" height="20"></td>
						</tr>
						<tr>
							<td class="login_txt2" align="right" width="40%">用户帐号:</td>
							<td class="tex_inpt" colspan="2" align="center" ><input type="text" style="WIDTH: 140px; FONT-FAMILY: Arial" size="20" name="username1" id="username1"  value="<% getInfo("normal-user"); %>"/></td>
						</tr>
						<tr>
							<td class="login_txt2" align="right" width="40%">密码:</td>
							<td class="tex_inpt" colspan="2" align="center" ><input type="password" style="WIDTH: 140px; FONT-FAMILY: Arial" size="20" name="psd1" id="psd1" /></td>
						</tr>
					</table>
				</td>
			</tr>
			<tr><td>&nbsp;</td></tr>
			<tr align="center" valign="middle" >
				<td>
				<input type="button" class="left_btn" onClick="on_submit();" value="用户登录"/>
			
				<input name="reg" class="right_btn" type="button" value="设备注册" <% checkWrite("dev_reg_btn"); %> onclick="location.href='/usereg.asp';">
				<input type="hidden" name="csrfmiddlewaretoken" value="KbyUmhTLMpYj7CD2di7JKP1P3qmLlkPt" />
				</td>

			</tr>
			<tr><td>&nbsp;</td></tr>
		</table>
	</td>

</tr>

</table>
<div class="version">
	<!--京ICP备05002571号＠中国移动通讯版权所有 -->
</div>
<input type="hidden" name="username" id="username" value=''>
<input type="hidden" name="psd" id="psd" value=''>
</form>
</BODY>
<%addHttpNoCache();%>
</html>
