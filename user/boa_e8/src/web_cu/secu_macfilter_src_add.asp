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
var rules = new Array();
with(rules){<% rteMacFilterList(); %>}

/********************************************************************
**          on document apply
********************************************************************/
function btnApply()
{
	/*
	if(form.devname.value == "")
	{
		alert("�������豸������Ϊ�գ�");
		return false;
	}
	*/
	//var cur_filtermode = 0;
	//cur_filtermode = (form.mode.value == "on") ? 1:0;//form.macFilterMode.value ;
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
	for(var i = 0; i < rules.length; i++)
	{
		if(/*rules[i].name == form.devname.value ||*/ rules[i].mac == form.mac.value)
		{
			alert( "�ù����Ѵ���");//alert("That rule already exists");
			return false;
		}
	}
	form.submit();
}

function RefreshPage()
{
	location.href = document.location.href;
}
</SCRIPT>
</HEAD>

<!-------------------------------------------------------------------------------------->
<!--��ҳ����-->
<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000">
  <blockquote>
	<DIV align="left" style="padding-left:20px; padding-top:5px">
		<form id="form" action=/boaform/admin/formRteMacFilter method=POST name="form">
			<b>MAC��ַ�������</b><br><br><br>
			<!--��ҳ���������˵�������·������ָ���������豸��MAC��ַ��<br>
			��"�������豸��"һ�������������Ƶľ������豸������"MAC��ַ"һ��������豸��MAC��ַ��<br>
			�����������������"ipconfig /all"���鿴����PC��MAC��ַ��<br> -->
			<table border="0" cellpadding="0" cellspacing="0" width="100%">
                  <tbody><tr>
                    <td>���˹������ƣ�</td>
                    <td><input type="text" name="name"maxlength="31"></td>
                    <td>&nbsp;</td>
                  </tr>
                  <tr>
                    <td>MAC��ַ��</td>
                    <td><input type="text" name="mac" maxlength="17"></td>
                    <td>����ʽ��AA:BB:CC:DD:EE:FF��</td>
                  </tr>
                  <tr>
				  	<td>
				  	</td>
				  </tr>
                  <tr>
				  	<td>
				  	</td>
				  </tr>
                </tbody>
            </table>
    		<p align="center">
				<input type="button" class="btnsaveup"  id="btnOK" value="ȷ��" onclick="btnApply()" >
				<input type="button" class="btnsaveup" id="btnCancel" value="ȡ��" onclick="RefreshPage()">
				<input type="hidden" name="action" value="ad">
				<input type="hidden" name="submit-url" value="/secu_macfilter_src.asp">
			</p>
		</form>
	</div>
  </blockquote>
</body>
<%addHttpNoCache();%></html>
