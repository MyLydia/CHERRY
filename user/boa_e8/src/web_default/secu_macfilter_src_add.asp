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
//var rule = new it_nr("rule_");
var mode = sji_queryparam("mode");
var index = mode ? sji_queryparam("index"):-1;
//rule.dec(paramrl);


/********************************************************************
**          on document apply
********************************************************************/
function on_init()
{
	sji_docinit(document, cgi);

	if(cgi.macFilterMode != undefined){
		var mode_row = table.insertRow(table.rows.length);
		var cell; // = row.insertCell(0);
		var tmp;
		cell = mode_row.insertCell(0);
		cell.innerHTML = "<table border=\"0\" cellpadding=\"0\" cellspacing=\"0\"><tr><td width=\"100\">����ģʽ";
		cell = mode_row.insertCell(1);
		tmp = "<td width=\"65\"><input name=\"macFilterMode\" value=\"off\"  type=\"radio\"";
		tmp += (cgi.macFilterMode)?"disabled":"checked";
		tmp += ">&nbsp;&nbsp;������</td>";	
		cell.innerHTML = tmp;
		cell = mode_row.insertCell(2);
		tmp = "<td width=\"65\"><input name=\"macFilterMode\" value=\"on\"  type=\"radio\" ";
		tmp += (cgi.macFilterMode)?"checked":"disabled";
		tmp += ">&nbsp;&nbsp;������</td></tr></table>";
		cell.innerHTML = tmp;
	}
	if(mode == 1)//edit mode
	{
		if(cgi.macFilterMode != undefined)
			form.macFilterMode.disabled = true;
		form.devname.value = rules[index].devname;	
		form.mac.value = rules[index].mac;
		/*form.enable.value = rules[index].enable?"on":"off";*/
		<% initPageMacFilter("edit_items"); %>	
	}
}

// ����ַ�����ֻ�ܰ������֣��ַ����»���
function checkstr(str)
{
	var ch="";
	if(typeof str != "string") return 0;
	for(var i =0;i< str.length; i++) {
		ch = str.charAt(i);
		if(!(ch =="_"||(ch<="9"&&ch>="0")||(ch<="z"&&ch>="a")||(ch<="Z"&&ch>="A"))) return 0;
	}
	return 1;
}
function btnApply()
{
	if(mode == 1)
	{
		form.action.value = "up";
		form.index.value = index;
	}
	else
	{
		form.action.value = "ad";
	}
	if(form.mac.value == "")
	{
		alert("mac ��ַ����Ϊ�գ�");
		return false;
	}
	if(!sji_checkmac(form.mac.value))
	{
		alert("mac ��ַ����");
		return false;
	}
	if(form.devname.value == ""||!checkstr(form.devname.value))
	{
		alert("�������豸��������");
		return false;
	}
	if((form.blocktimes != undefined) &&(form.blocktimes.value == ""||isNaN(form.blocktimes.value)||parseInt(form.blocktimes.value)<0||parseInt(form.blocktimes.value)>4294967295 ))
	{
		alert("���ش���������");
		return false;
	}
	for(var i = 0; i < rules.length; i++)
	{
		if(cgi.macFilterMode == undefined || ((form.macFilterMode.value=="off") && (rules[i].mode==0))||((form.macFilterMode.value=="on") && (rules[i].mode==1)))
			if((rules[i].mac == form.mac.value)&&(mode!=1 || index!=i))
			{
				alert( "MAC��ַ�Ѵ���");//alert("That rule already exists");
				return false;
			}
	}
	for(var i = 0; i < rules.length; i++)
	{
		if(cgi.macFilterMode == undefined || ((form.macFilterMode.value=="off") && (rules[i].mode==0))||((form.macFilterMode.value=="on") && (rules[i].mode==1)))
			if((rules[i].devname == form.devname.value)&&(mode!=1 || index!=i))
			{
				alert( "�������豸���Ѵ���");//alert("That rule already exists");
				return false;
			}
	}
	if(cgi.macFilterMode != undefined){
 		if((form.macFilterMode.value=="on") && (cgi.macFilterMode == 0))
			if(!confirm("�����Ǻ�����ģʽ, ��ȷ��Ҫ��Ӱ�����ģʽ��MAC��ַ��?"))
				return false;
		if((form.macFilterMode.value=="off") && (cgi.macFilterMode == 1))
				if(!confirm("�����ǰ�����ģʽ, ��ȷ��Ҫ��Ӻ�����ģʽ��MAC��ַ��?"))
					return false;
	}
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	form.submit();
}
</SCRIPT>
</HEAD>

<!-------------------------------------------------------------------------------------->
<!--��ҳ����-->
<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000" onLoad="on_init();">
  <blockquote>
	<DIV align="left" style="padding-left:20px; padding-top:5px">
		<form id="form" action=/boaform/admin/formRteMacFilter method=POST name="form">
			<b>���MAC ��ַ���˹���</b><br><br><br>
			<!--��ҳ���������˵�������·������ָ���������豸��MAC��ַ��<br>
			��"�������豸��"һ�������������Ƶľ������豸������"MAC��ַ"һ��������豸��MAC��ַ��<br>
			�����������������"ipconfig /all"���鿴����PC��MAC��ַ��<br> -->
			<hr align="left" class="sep" size="1" width="90%">
			<table id="table" border="0" cellpadding="0" cellspacing="0">
			</table>
			<table border="0" cellpadding="0" cellspacing="0">
				<!--<tr style="display:none">
					<td width="100">�������豸��</td>
					<td><input type="text" name="devname" size="18" ></td>
				</tr>-->
				<tr>
					<td width="100">�������豸��&nbsp;</td>
					<td><input type="text" name="devname" size="18"></td>
				</tr>
				<tr>
					<td width="100">MAC��ַ&nbsp;</td>
					<td><input type="text" name="mac" size="18"></td>
					<td>(xx-xx-xx-xx-xx-xx)</td>
				</tr>
			</table>
			<!--<table border="0" cellpadding="0" cellspacing="0">
				<tr>
					<td width="180">ʹ��&nbsp</td>
					<td><input type="radio" name="enable" value="on" checked >&nbsp;&nbsp;enable</td>
					<td><input type="radio" name="enable" value="off" >&nbsp;&nbsp;disable</td>
				</tr>
			</table>-->
			<% initPageMacFilter("add_items"); %> 
			<hr align="left" class="sep" size="1" width="90%">
			<input type="button" class="button" value="����/Ӧ��" onClick="btnApply()">
			<input type="hidden" name="action" value="ad">
			<input type="hidden" name="index" value="0">
			<input type="hidden" name="submit-url" value="/secu_macfilter_src.asp">
			<input type="hidden" name="postSecurityFlag" value="">
		</form>
	</div>
  </blockquote>
</body>
<%addHttpNoCache();%></html>
