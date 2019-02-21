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
<script>
/********************************************************************
**          on document load
********************************************************************/
function on_init()
{
	//document.forms[0].username1.focus();

	if(document.referrer.search("usereg.asp") != -1)
		return ;

	<% checkPopupRegPage(); %>
}
</script>
</head>

<body leftmargin="0" topmargin="0"  bgcolor="white" onLoad="on_init();">
<form action=/boaform/admin/formLogin method=POST name="cmlogin" autocomplete="off">
<div id="login" class="Unicom_bg">
	<p class="site">网上营业厅 www.10010.com  &nbsp;&nbsp; 客服热线10010  &nbsp;&nbsp; 充值专线10011</p>
	<div class="login_admin">
		<div id="welcome">
			<h1 class="welcome">WELCOME</h1>
			<div class="login">
				<a class="admin" href="login_admin.asp"></a>
				<a class="others" href="login_others.asp"></a>
			</div>
		<div class="login_txt">
			<span class="admin_txt">管理员账户</span>
			<span>其他账户</span>
		</div>
	<!--	<input type="button" class="left_btn" onClick="on_submit();" value="用户登录" height="20" width="30"/>  
		<input name="reg" class="btn_dis" type="button" value="设备注册" <% checkWrite("dev_reg_btn"); %> onclick="location.href='/usereg.asp';">  -->
		<input type="hidden" name="csrfmiddlewaretoken" value="KbyUmhTLMpYj7CD2di7JKP1P3qmLlkPt" />		
		</div>

</div>

<input type="hidden" name="username" id="username" value=''>
<input type="hidden" name="psd" id="psd" value=''>
<input type='hidden' name='csrftoken' value='16528d8f5bb5eeaab5f052009722cd41' />
</form>
</BODY>
<%addHttpNoCache();%>
</html>
