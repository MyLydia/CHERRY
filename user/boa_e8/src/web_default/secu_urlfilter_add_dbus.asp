<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<!--系统默认模板-->
<HTML>
<HEAD>
<TITLE>URL访问设置</TITLE>
<META http-equiv=pragma content=no-cache>
<META http-equiv=cache-control content="no-cache, must-revalidate">
<META http-equiv=content-type content="text/html; charset=gbk">
<META http-equiv=content-script-type content=text/javascript>
<!--系统公共css-->
<STYLE type=text/css>
@import url(/style/default.css);
</STYLE>
<!--系统公共脚本-->
<SCRIPT language="javascript" src="common.js"></SCRIPT>
<SCRIPT language="javascript" type="text/javascript">
var cgi = new Object();
var rules = new Array();
with(rules){<% initPageURL(); %>}

/********************************************************************
**          on document submit
********************************************************************/
function btnApply()
{
	with ( document.forms[0] ) {
		if(name.length == "")
		{
			alert("名称不可为空");
			return;
		}
		
		var surl = sji_killspace(url.value);

		if (surl.length == 0)
		{
			alert( "Url 地址不可为空");
			return;
		}
		//if (!sji_checklen(surl.length, 1, 100))
		if (surl.length>=100)
		{
			alert( "Url 地址长度必须不超过100个字符");
			return;
		}

		for (var i=0; i < surl.length; i++)
		{
			if (surl.charAt(i) == " ") {
				alert("无效的URL地址");
				return;
			}
		}

		if (surl == "www.") {
			alert("无效的URL地址");
			return;
		}
		/*if(!sji_checkurl(surl))
		{
			alert("无效的URL地址");
			return;
		}*/
		for(var i = 0; i < rules.length; i++)
		{
			if(rules[i].url == surl)
			{
				alert( "该规则已存在");
				return;
			}
		}

		url.value = surl;
		var urlFilterMacList = mac.value.split(",");
		for (var i = 0; i < urlFilterMacList.length; i++)
		{
			if(urlFilterMacList[i]!="" && !sji_checkmac2(urlFilterMacList[i]))
			{
				mac.value ="";
				mac.focus();
				alert("MAC地址输入非法，请重新输入！");
				return;
			}
		}
		postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);

		submit();
	}
}
</SCRIPT>
</HEAD>

<!-------------------------------------------------------------------------------------->
<!--主页代码-->
<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000">
	<blockquote>
		<DIV align="left" style="padding-left:20px; padding-top:5px">
			<form id="form" action=/boaform/admin/formURL method=POST name="form">
				<div align="left">
					<b>添加URL过滤规则</b>
					<br><br>
					添加规则时请正确输入URL地址，该规则将在点击“保存”按钮后生效.
					<br><br>
					<hr align="left" class="sep" size="1" width="90%">
					<table border="0" cellpadding="0" cellspacing="0">
						<tr nowrap>
							<td width="180">名称:</td>
							<td><input type="text" name="name"></td>
						</tr>
						<tr nowrap>
							<td width="180">URL地址:</td>
							<td><input type="text" name="url"></td>
						</tr>
						<tr nowrap>
							<td width="180">MAC地址(xx:xx:xx:xx:xx:xx):</td>
							<td><input type="text" name="mac"></td>
						</tr>
						<tr nowrap>
							<td width="180">使能/禁止:</td>
							<td><input type="radio" name="Enable" value="0" checked>&nbsp;&nbsp;禁止</td>
							<td><input type="radio" name="Enable" value="1" >&nbsp;&nbsp;使能</td>
						</tr>
					</table>
				</div>
				<hr align="left" class="sep" size="1" width="90%">
				<input type="button" class="button" value="保存" name="save" onClick="btnApply()">
				<input type="hidden" id="action" name="action" value="ad">
				<input type="hidden" name="submit-url" value="/secu_urlfilter_cfg_dbus.asp">
				<input type="hidden" name="postSecurityFlag" value="">
			</form>
		</div>
	</blockquote>
</body>
<%addHttpNoCache();%>
</html>
