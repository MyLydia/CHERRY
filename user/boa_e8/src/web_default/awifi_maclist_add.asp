<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<!--系统默认模板-->
<HTML>
<HEAD>
<TITLE>AWiFi MAC地址白名单</TITLE>
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
<% aWifiTrustedMacList(); %>

function on_sel()
{
	with(form)
	{
		for(var i = 0; i <lstrc.rows.length; i++)
		{
			lstrc.rows[i].cells[0].children[0].click();
		}
	}
}

/********************************************************************
**          on document load
********************************************************************/
function on_init()
{
	sji_docinit(document);
}

/********************************************************************
**          on document submit
********************************************************************/
function on_submit()
{
	with ( document.forms[0] )
	{
		//////////
		if(mac.value.length == 0 || sji_checkmac2(mac.value) == false)
		{
			mac.focus();
			alert("MAC地址\"" + mac.value + "\"为无效MAC地址，请重新输入！");
			return;
		}

		for(var i = 0; i < rules.length; i++)
		{
			if(rules[i].mac == mac.value)
			{
				alert( "该规则已存在");
				return false;
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
<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000" onLoad="on_init();">
	<blockquote>
		<DIV align="left" style="padding-left:20px; padding-top:5px">
			<form id="form" action="/boaform/admin/formaWifiTrustedMac" method="post">
				<div align="left">
					<b>添加MAC地址白名单规则</b><br>
					<br>
					<table border="0" cellpadding="0" cellspacing="0">
					   <tr>
						  <td width="180px">MAC地址(xx:xx:xx:xx:xx:xx):</td>
						  <td><input type="text" size="17" name="mac" style="width:150px"></td>
					   </tr>
					</table>
					<br><br>
					<table id="lstrc" border="0" cellpadding="0" cellspacing="0"></table>
				</div>
				<hr align="left" class="sep" size="1" width="90%">
				<INPUT type="button" class="button" value="保存/应用" onClick="on_submit();">
				<input type="hidden" name="action" value="ad">
				<input type="hidden" name="portNum" value="0">
				<input type="hidden" name="ifname" value="">
				<input type="hidden" name="submit-url" value="/awifi_maclist.asp">
				<input type="hidden" name="postSecurityFlag" value="">
			</form>
		</DIV>
	</blockquote>
</body>
<%addHttpNoCache();%>
</html>
