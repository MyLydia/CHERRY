<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<!--ϵͳĬ��ģ��-->
<HTML>
<HEAD>
<TITLE>��������������</TITLE>
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
with(rules){<% rteMacFilterList(); %>}

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
	
	if(cgi.macFilterEnble == false)
	{
		form.add.disabled = true;
		form.remove.disabled = true;
		if(cgi.macFilterMode != undefined)
			form.macFilterMode.disabled = true;
		document.getElementById("macfilter_list").style.display="none";	
	}
	//add mac filter mode selection
	if(cgi.macFilterMode != undefined){
		var mode_row = filtermode.insertRow(filtermode.rows.length);
		var cell; // = row.insertCell(0);
		var tmp;
		cell = mode_row.insertCell(0);
		cell.innerHTML = "����ģʽ:";
		cell = mode_row.insertCell(1);
		tmp = "<input name=\"macFilterMode\" value=\"off\" onclick=\"change_mode('off')\" type=\"radio\" ";
		tmp += (cgi.macFilterMode)?"":"checked";
		tmp += ">&nbsp;&nbsp;������";	
		cell.innerHTML = tmp;
		cell = mode_row.insertCell(2);
		tmp = "<input name=\"macFilterMode\" value=\"on\" onclick=\"change_mode('on')\" type=\"radio\" ";
		tmp += (cgi.macFilterMode)?"checked":"";
		tmp += ">&nbsp;&nbsp;������";
		cell.innerHTML = tmp;
		cell = mode_row.insertCell(3);
		cell.style.color="red";
		cell.innerHTML = "&nbsp;&nbsp;&nbsp;&nbsp;����������������ͬʱ���򿪣����������Ч������������Ч��";
	}


	if(rulelst.rows)
	{
		while(rulelst.rows.length > 1)
			rulelst.deleteRow(1);
	}

	for(var i = 0; i < rules.length; i++)
	{
		var row = rulelst.insertRow(i + 1);
		var j = 0;
		row.nowrap = true;
		row.vAlign = "top";
		row.align = "center"

		var cell; // = row.insertCell(0);
		cell = row.insertCell(j++);
		cell.innerHTML = rules[i].devname;
		cell = row.insertCell(j++);
		cell.innerHTML = rules[i].mac;
		/*cell.innerHTML = rules[i].enable?"enable":"disable";*/
		<% initPageMacFilter("table_cell"); %>
		cell = row.insertCell(j++);
		cell.innerHTML = "<input type=\"checkbox\" name=\"check"+i+"\" onClick=\"on_chkclick(" + i + ");\">";
		cell = row.insertCell(j++);
		cell.innerHTML = "<input type=\"button\" name=\"edit\" class=\"button\" onClick=\"addClick(" + i + ")\" value=\"�༭\">";
	}

	if(rules.length == 0)
	{
		form.remove.disabled = true;
	}
}

function addClick(act)
{
   var loc = "secu_macfilter_src_add.asp" + ((act+1) ? ("?index="+ act + "&mode=1"):"?mode=0");   
   var code = "window.location.href=\"" + loc + "\"";
   eval(code);
}

function removeClick()
{
	with ( document.forms[0] )
	{
		form.bcdata.value = sji_encode(rules, "select");
		postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
		submit();
	}
}

function on_action(act)
{
	form.action.value = act;
	if(form.macFilterEnble.value == "off")
		if(!confirm("�Ƿ�Ҫ�ر�MAC��ַ����?")){
			form.macFilterEnble.value = "on";
			return false;
		}
	if(form.macFilterEnble.value == "on")
		if(!confirm("�Ƿ�Ҫ����MAC��ַ����?")){
			form.macFilterEnble.value = "off";
			return false;
		}
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	
	with(form)
	{
		submit();
	}
}
function change_mode(act)
{
	form.action.value = "mode";
	if(cgi.macFilterMode != undefined){
		var tmp;
		if(form.macFilterMode.value == "off")
			if(!confirm("�Ƿ�Ҫ�л���������?")){
			form.macFilterMode.value = "on";
			return false;
		}		
		if(form.macFilterMode.value == "on")
			if(!confirm("�Ƿ�Ҫ�л���������?")){
			form.macFilterMode.value = "on";
			return false;
		}
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
		<form id="form" action=/boaform/admin/formRteMacFilter method=POST name="form">
			<b>MAC��ַ���� -- ���������� 16 ������.</b><br>
			<hr align="left" class="sep" size="1" width="90%">
			<table id="filtermode" border="0" cellpadding="2" cellspacing="0">
				<tr>
					<td>MAC��ַ����:</td>
					<td><input type="radio" name="macFilterEnble" value="off" onClick="on_action('sw')">&nbsp;&nbsp;����</td>
					<td><input type="radio" name="macFilterEnble" value="on" onClick="on_action('sw')">&nbsp;&nbsp;����</td>
				</tr>
			</table>
			<br>
			<div id="macfilter_list" style="display:block">
			<table id="rulelst" name="blacklst" width="500px" style="display:block" border="1" cellpadding="2" cellspacing="0">
			   <tr class="hd" align="center">
				  <td width="150px">�������豸��</td>
				  <td width="200px">MAC��ַ</td>
				  <!--<td width="100px">ʹ��</td>-->
				  <% initPageMacFilter("table_title"); %>
				  <td width="25px">�Ƴ�</td>
				  <td width="25px">�༭</td>
			   </tr>
			</table>
			<br>
			<hr align="left" class="sep" size="1" width="90%">
			<input type="button" name="add" class="button" onClick="addClick(-1)" value="���">
			<input type="button" name="remove" class="button" onClick="removeClick()" value="ɾ��">
			</div>
			<input type="hidden" name="action" value="rm">
			<input type="hidden" name="bcdata" value="le">
			<input type="hidden" name="submit-url" value="/secu_macfilter_src.asp">
			<input type="hidden" name="postSecurityFlag" value="">
		</form>
		</div>
	</blockquote>
</body>
<%addHttpNoCache();%>
</html>
