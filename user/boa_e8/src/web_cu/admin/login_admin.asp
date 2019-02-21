<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<HTML>
<HEAD>
<TITLE>Unicom</TITLE>
<META http-equiv=pragma content=no-cache>
<META http-equiv=cache-control content="no-cache, must-revalidate">
<META http-equiv=content-type content="text/html; charset=gbk">
<META http-equiv=content-script-type content=text/javascript>
<style type=text/css>
@import url(/style/default.css);
</style>
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
**          on document submit
********************************************************************/
function on_submit() 
{
	if (loginFlag)
		return 1;
	
	with ( document.forms[0] ) {
		{
			//username.value = username1.value;
			psd.value = psd1.value;
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

</head>
<body>
<form action=/boaform/admin/formLogin method=POST name="cmlogin">
<div class="Unicom_bg">
	<p class="site">网上营业厅 www.10010.com  &nbsp;&nbsp; 客服热线10010  &nbsp;&nbsp; 充值专线10011</p>
	<div id="login_admin" class="login_admin" style="padding-top:140px;">
		<a style="padding-right:0;" class="admin" href="#"></a>
		<p>管理员账户</p>
		<div class="login_ipt">
			<input class="paswd" name="psd1" id="psd1" type="password" maxlength="64">
			<input class="paswd_go" type="button" name="paswd_go" value=" " onclick="return on_submit()"/>
		</div>
		<input class="back" type="button" name="back" value="返回" onclick="window.location='login.asp'">
		<!--  <input type="hidden" name="username" id="username" value=''>  -->
		<input type="hidden" name="psd" id="psd" value=''>	
		<input type="hidden" name="username" id="username"  value="<% getInfo("super-user"); %>"/>	
		<input  type="hidden" NAME="submit.htm?login_admin.asp" value="Send">
	</div>
</div>
</form>
</body>
</html>
