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
with(rules){<% initPageURL(); %>}

/********************************************************************
**          on document submit
********************************************************************/
function btnApply()
{
	with ( document.forms[0] ) {
		if(name.length == "")
		{
			alert("���Ʋ���Ϊ��");
			return;
		}
		
		var surl = sji_killspace(url.value);

		if (surl.length == 0)
		{
			alert( "Url ��ַ����Ϊ��");
			return;
		}
		//if (!sji_checklen(surl.length, 1, 100))
		if (surl.length>=100)
		{
			alert( "Url ��ַ���ȱ��벻����100���ַ�");
			return;
		}

		for (var i=0; i < surl.length; i++)
		{
			if (surl.charAt(i) == " ") {
				alert("��Ч��URL��ַ");
				return;
			}
		}

		if (surl == "www.") {
			alert("��Ч��URL��ַ");
			return;
		}
		/*if(!sji_checkurl(surl))
		{
			alert("��Ч��URL��ַ");
			return;
		}*/
		for(var i = 0; i < rules.length; i++)
		{
			if(rules[i].url == surl)
			{
				alert( "�ù����Ѵ���");
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
				alert("MAC��ַ����Ƿ������������룡");
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
<!--��ҳ����-->
<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000">
	<blockquote>
		<DIV align="left" style="padding-left:20px; padding-top:5px">
			<form id="form" action=/boaform/admin/formURL method=POST name="form">
				<div align="left">
					<b>���URL���˹���</b>
					<br><br>
					��ӹ���ʱ����ȷ����URL��ַ���ù����ڵ�������桱��ť����Ч.
					<br><br>
					<hr align="left" class="sep" size="1" width="90%">
					<table border="0" cellpadding="0" cellspacing="0">
						<tr nowrap>
							<td width="180">����:</td>
							<td><input type="text" name="name"></td>
						</tr>
						<tr nowrap>
							<td width="180">URL��ַ:</td>
							<td><input type="text" name="url"></td>
						</tr>
						<tr nowrap>
							<td width="180">MAC��ַ(xx:xx:xx:xx:xx:xx):</td>
							<td><input type="text" name="mac"></td>
						</tr>
						<tr nowrap>
							<td width="180">ʹ��/��ֹ:</td>
							<td><input type="radio" name="Enable" value="0" checked>&nbsp;&nbsp;��ֹ</td>
							<td><input type="radio" name="Enable" value="1" >&nbsp;&nbsp;ʹ��</td>
						</tr>
					</table>
				</div>
				<hr align="left" class="sep" size="1" width="90%">
				<input type="button" class="button" value="����" name="save" onClick="btnApply()">
				<input type="hidden" id="action" name="action" value="ad">
				<input type="hidden" name="submit-url" value="/secu_urlfilter_cfg_dbus.asp">
				<input type="hidden" name="postSecurityFlag" value="">
			</form>
		</div>
	</blockquote>
</body>
<%addHttpNoCache();%>
</html>
