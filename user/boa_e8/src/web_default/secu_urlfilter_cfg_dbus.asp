<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<!--ϵͳĬ��ģ��-->
<HTML>
<HEAD>
<TITLE>URL��������</TITLE>
<META http-equiv=pragma content=no-cache>
<META http-equiv=cache-control content="no-cache, must-revalidate">
<META http-equiv=content-type content="text/html; charset=gbk">
<META http-equiv=content-script-type content=text/javascript>
<!--ϵͳ����css-->
<STYLE type=text/css>
@import url(/style/default.css);
</STYLE>
<!--ϵͳ�����ű�-->
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
			cell.innerHTML = "ʹ��";
		else
			cell.innerHTML = "��ֹ";
		
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
		alert("����ѡ��Ҫ�޸ĵĹ���!");
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
			alert("���Ʋ���Ϊ��");
			return false;
		}
		
		var surl = sji_killspace(url.value);

		if (surl.length == 0)
		{
			alert( "Url ��ַ����Ϊ��");
			return false;
		}
		//if (!sji_checklen(surl.length, 1, 100))
		if (surl.length>=100)
		{
			alert( "Url ��ַ���ȱ��벻����100���ַ�");
			return false;
		}

		for (var i=0; i < surl.length; i++)
		{
			if (surl.charAt(i) == " ") {
				alert("��Ч��URL��ַ");
				return false;
			}
		}

		if (surl == "www.") {
			alert("��Ч��URL��ַ");
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
				alert("MAC��ַ����Ƿ������������룡");
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
			alert("����ѡ��Ҫɾ���Ĺ���!");
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
<!--��ҳ����-->
<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000" onLoad="on_init();">
	<blockquote>
		<DIV align="left" style="padding-left:20px; padding-top:5px">
			<form id="form" action=/boaform/admin/formURL method=POST name="form">
				<b>URL���� -- ������������ 100������.</b><br><br>
				<div id="rstip" style="display:none;"><font color="red">��ʾ����ҳ������ã���Ҫ����·����������Ч��</font><br></div>
				<hr align="left" class="sep" size="1" width="90%">
				<br>
				<table id="rulelst" class="flat" border="1" cellpadding="2" cellspacing="0">
					<tr align="center" class="hd">
						<td width="120px">����</td>
						<td width="120px">URL��ַ</td>
						<td width="120px">MAC��ַ</td>
						<td width="120px">����/ʹ��</td>
						<td width="60px">ѡ��</td>
					</tr>
				</table>
				<br>
				<div id="input_div">
					<hr align="left" class="sep" size="1" width="90%">
						<table border="0" cellpadding="0" cellspacing="0">
						<tr>
							<td width="180">����:</td>
							<td><input type="text" name="name" id="name"></td>
						</tr>
						<tr>
							<td width="180">URL��ַ:</td>		
							<td><input type="text" name="url" id="url"></td>		
						</tr>					
						<tr>						
							<td width="180">MAC��ַ(xx:xx:xx:xx:xx:xx):</td>				
							<td><input type="text" name="mac" id="mac"></td>		
						</tr>					
						<tr>					
							<td width="180">ʹ��/��ֹ:</td>			
							<td><input type="radio" name="Enable" value="0" checked>&nbsp;&nbsp;��ֹ</td>		
							<td><input type="radio" name="Enable" value="1" >&nbsp;&nbsp;ʹ��</td>			
						</tr>
						<tr>
							<td  class="td2">
								<input type="submit" class="button2" value="����" id="modify" onclick="return ModifyApply();" />
								<input name="back" type="button" id="back" value="ȡ ��"  class="button2" onclick="back2add()"/>
							</td>
						</tr>
					</table>
				</div>
				<br>
				<hr align="left" class="sep" size="1" width="90%">
				<input type="button" class="button" name="add" onClick="addClick()" value="���">
				<input type="button" class="button" name="modify" onClick="modifyClick()" value="�޸�">
				<input type="button" class="button" name="remove" onClick="on_action('rm')" value="ɾ��">
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
