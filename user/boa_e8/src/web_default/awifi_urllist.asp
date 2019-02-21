<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<!--系统默认模板-->
<HTML>
<HEAD>
<TITLE>AWiFi域名白名单设置</TITLE>
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
with(rules){<% aWifiTrustedUrlList(); %>}

function on_chkclick(index)
{
	if(index < 0 || index >= rules.length)
		return;
	rules[index].select = !rules[index].select;
}

/********************************************************************
**          on document load
********************************************************************/
function on_init()
{
	sji_docinit(document, cgi);

	if(cgi.aWifiEnble == false)
	{
		form.add.disabled = true;
		form.remove.disabled = true;
	}

	if(rulelst.rows)
	{
		while(rulelst.rows.length > 1)
			rulelst.deleteRow(1);
	}

	for(var i = 0; i < rules.length; i++)
	{
		var row = rulelst.insertRow(i + 1);

		row.nowrap = true;
		row.vAlign = "top";
		row.align = "center";

		var cell = row.insertCell(0);
		cell.innerHTML = rules[i].url;
		cell = row.insertCell(1);
		cell.innerHTML = "<input type=\"checkbox\" onClick=\"on_chkclick(" + i + ");\">";
	}

	if(rules.length == 0)
	{
		form.remove.disabled = true;
	}	
}

function addClick()
{
   var loc = "awifi_urllist_add.asp";
   var code = "window.location.href=\"" + loc + "\"";
   eval(code);
}

function on_action(act)
{
	form.action.value = act;

	if(act == "rm" && rules.length > 0)
	{
		form.bcdata.value = sji_encode(rules, "select");
	}
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	
	with(form)
	{
		submit();
	}
}
</SCRIPT>
</HEAD>
<!-------------------------------------------------------------------------------------->
<!--主页代码-->
<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000" onLoad="on_init();">
	<blockquote>
		<DIV id="cfg" align="left" style="padding-left:20px; padding-top:5px">
			<form id="form" action=/boaform/admin/formaWifiTrustedUrl method=POST>
				<b>AWiFi功能设置.</b><br><br>
				<hr align="left" class="sep" size="1" width="90%">
				<table border="0" cellpadding="2" cellspacing="0" style="display:none">
					<tr>
						<td>AWiFi功能:</td>
						<td><input type="radio" name="aWifiEnble" value="off" onClick="on_action('sw')">&nbsp;&nbsp;禁用</td>
						<td><input type="radio" name="aWifiEnble" value="on" onClick="on_action('sw')">&nbsp;&nbsp;启用</td>
					</tr>
				</table>
				<br><br>
				
				<b>AWiFi域名白名单.</b><br><br>
				<table id="rulelst" class="flat" border="1" cellpadding="2" cellspacing="0">
					<tr align="center" class="hd">
						<td width="180">域名</td>
						<td>删除</td>
					</tr>
				</table>
				<br>
				
				<hr align="left" class="sep" size="1" width="90%">
				<input type="button" name="add" class="button" onClick="addClick()" value="添加">
				<input type="button" name="remove" class="button" onClick="on_action('rm')" value="删除">
				<input type="hidden" id="action" name="action" value="none">
				<input type="hidden" name="bcdata" value="le">
				<input type="hidden" name="submit-url" value="/awifi_urllist.asp" >
				<input type="hidden" name="postSecurityFlag" value="">
			</form>
		</div>
	</blockquote>
</body>
<%addHttpNoCache();%>
</html>
