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
var act_idx = -1;
with(rules){<% initPageURL(); %>}

function on_chkclick(index)
{
	if(index < 0 || index >= rules.length)
		return;
	rules[index].select = !rules[index].select;
	act_idx = index;
}

/********************************************************************
**          on document load
********************************************************************/
function on_init()
{
	sji_docinit(document, cgi);

	document.getElementById("input_div").style.display="none";
	
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
		cell.innerHTML = rules[i].name;
		
		cell = row.insertCell(1);
		cell.innerHTML = rules[i].url;
		cell.align = "left";
		
		cell = row.insertCell(2);
		cell.innerHTML = rules[i].mac;
		
		cell = row.insertCell(3);
		if(rules[i].Enable == 1)
			cell.innerHTML = "使能";
		else
			cell.innerHTML = "禁止";
		
		cell = row.insertCell(4);
		cell.innerHTML = "<input type=\"radio\" name=\"act_select\" onClick=\"on_chkclick(" + i + ");\">";
	}
}

function addClick()
{
   var loc = "secu_urlfilter_add_dbus.asp";
   var code = "window.location.href=\"" + loc + "\"";
   eval(code);
}

function modifyClick()
{
	if(act_idx == -1)
	{
		alert("请先选择要修改的规则!");
		return false;
	}

	document.getElementById("input_div").style.display="";

	document.getElementById("name").value = rules[act_idx].name;
	document.getElementById("url").value = rules[act_idx].url;
	document.getElementById("mac").value = rules[act_idx].mac;
	if(rules[act_idx].Enable == 1)
		document.form.Enable[1].checked = true;
	else
		document.form.Enable[0].checked = true;
	
	return true;
}

function ModifyApply()
{
	document.getElementById("action").value="modify";
	document.getElementById("idx").value=act_idx;

	with ( document.forms[0] ) {
		if(name.length == "")
		{
			alert("名称不可为空");
			return false;
		}
		
		var surl = sji_killspace(url.value);

		if (surl.length == 0)
		{
			alert( "Url 地址不可为空");
			return false;
		}
		//if (!sji_checklen(surl.length, 1, 100))
		if (surl.length>=100)
		{
			alert( "Url 地址长度必须不超过100个字符");
			return false;
		}

		for (var i=0; i < surl.length; i++)
		{
			if (surl.charAt(i) == " ") {
				alert("无效的URL地址");
				return false;
			}
		}

		if (surl == "www.") {
			alert("无效的URL地址");
			return false;
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
				return false;
			}
		}
	}
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	return true;
}

function back2add()
{
	document.getElementById("idx").value=-1;
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	getObj("form").submit();
}

function on_action(act)
{
	form.action.value = act;

	if(act == "rm")
	{
		if(act_idx == -1)
		{
			alert("请先选择要删除的规则!");
			return false;
		}
		document.getElementById("idx").value=act_idx;
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
		<DIV align="left" style="padding-left:20px; padding-top:5px">
			<form id="form" action=/boaform/admin/formURL method=POST name="form">
				<b>URL过滤 -- 最多允许您添加 100条规则.</b><br><br>
				<div id="rstip" style="display:none;"><font color="red">提示：本页面的设置，需要重启路由器才能生效！</font><br></div>
				<hr align="left" class="sep" size="1" width="90%">
				<br>
				<table id="rulelst" class="flat" border="1" cellpadding="2" cellspacing="0">
					<tr align="center" class="hd">
						<td width="120px">名称</td>
						<td width="120px">URL地址</td>
						<td width="120px">MAC地址</td>
						<td width="120px">规则/使能</td>
						<td width="60px">选择</td>
					</tr>
				</table>
				<br>
				<div id="input_div">
					<hr align="left" class="sep" size="1" width="90%">
						<table border="0" cellpadding="0" cellspacing="0">
						<tr>
							<td width="180">名称:</td>
							<td><input type="text" name="name" id="name"></td>
						</tr>
						<tr>
							<td width="180">URL地址:</td>		
							<td><input type="text" name="url" id="url"></td>		
						</tr>					
						<tr>						
							<td width="180">MAC地址(xx:xx:xx:xx:xx:xx):</td>				
							<td><input type="text" name="mac" id="mac"></td>		
						</tr>					
						<tr>					
							<td width="180">使能/禁止:</td>			
							<td><input type="radio" name="Enable" value="0" checked>&nbsp;&nbsp;禁止</td>		
							<td><input type="radio" name="Enable" value="1" >&nbsp;&nbsp;使能</td>			
						</tr>
						<tr>
							<td  class="td2">
								<input type="submit" class="button2" value="保存" id="modify" onclick="return ModifyApply();" />
								<input name="back" type="button" id="back" value="取 消"  class="button2" onclick="back2add()"/>
							</td>
						</tr>
					</table>
				</div>
				<br>
				<hr align="left" class="sep" size="1" width="90%">
				<input type="button" class="button" name="add" onClick="addClick()" value="添加">
				<input type="button" class="button" name="modify" onClick="modifyClick()" value="修改">
				<input type="button" class="button" name="remove" onClick="on_action('rm')" value="删除">
				<input type="hidden" id="action" name="action" value="none">
				<input type="hidden" name="idx" id="idx">
				<input type="hidden" name="submit-url" value="/secu_urlfilter_cfg_dbus.asp" >
				<input type="hidden" name="postSecurityFlag" value="">
			</form>
		</div>
	</blockquote>
</body>
<%addHttpNoCache();%>
</html>
