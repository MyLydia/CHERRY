<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<!--ϵͳĬ��ģ��-->
<HTML>
<HEAD>
<TITLE>AWiFi����������</TITLE>
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
with(rules){<% aWifiTrustedUrlList(); %>}

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
		/*if(!sji_checkurl(surl))
		{
			alert("��Ч��URL��ַ");
			return false;
		}*/
		for(var i = 0; i < rules.length; i++)
		{
			if(rules[i].url == surl)
			{
				alert( "�ù����Ѵ���");
				return false;
			}
		}

		url.value = surl;
		postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
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
			<form id="form" action="/boaform/admin/formaWifiTrustedUrl" method="post">
				<div align="left">
					<b>�����������������</b><br>
					<br>
					<table border="0" cellpadding="0" cellspacing="0">
					   <tr>
						  <td width="180">����</td>
						  <td><input type="text" name="url"></td>
					   </tr>
					</table>
					<br><br>
					<table id="lstrc" border="0" cellpadding="0" cellspacing="0"></table>
				</div>
				<hr align="left" class="sep" size="1" width="90%">
				<INPUT type="button" class="button" value="����/Ӧ��" onClick="on_submit();">
				<input type="hidden" name="action" value="ad">
				<input type="hidden" name="portNum" value="0">
				<input type="hidden" name="ifname" value="">
				<input type="hidden" name="submit-url" value="/awifi_urllist.asp">
				<input type="hidden" name="postSecurityFlag" value="">
			</form>
		</DIV>
	</blockquote>
</body>
<%addHttpNoCache();%>
</html>
