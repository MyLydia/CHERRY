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
function on_submit() 
{

	with ( document.forms[0] ) {
		psd.value = psd1.value;
		
		if(psd.value.length <= 0) {
			alert("����Ϊ�գ�����������!");
			return;
		}
		loginFlag = 1;
		
		submit();
	}
}
function key_submit()
{
	if(event.keyCode ==13)
	on_submit();
}
</SCRIPT>
</head>
<body>
<form action=/boaform/admin/formLogin method=POST name="cmlogin" autocomplete="off">
<div class="Unicom_bg" onKeyDown = "key_submit()">
	<p class="site">����Ӫҵ�� www.10010.com  &nbsp;&nbsp; �ͷ�����10010  &nbsp;&nbsp; ��ֵר��10011</p>
	<div class="login_admin" style="padding-top:140px;">
		<a style="padding-right:0;" class="others" href="#"></a>
		<p>�����˻�</p>
		<div class="login_ipt">
			<input class="paswd" name="psd1" id="psd1" type="password" maxlength="64">
			<input class="paswd_go" type="button" name="paswd_go" value=" " onclick="return on_submit()"/>
		</div>
		<input class="back" type="button" name="back" value="����" onclick="window.location='login.asp'">	
		<input type="hidden" name="psd" id="psd" value=''>	
		<input type="hidden" name="username" id="username"  value="<% getInfo("normal-user"); %>"/>	
		<input  type="hidden" NAME="submit.htm?login_others.asp" value="Send">
	</div>
</div>
</form>
</body>
</html>
