<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<!--ϵͳĬ��ģ��-->
<HTML>
<HEAD>
<TITLE>AWiFi��������</TITLE>
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

/********************************************************************
**          on document load
********************************************************************/
var cgi = new Object();
<%initaWifiAudit();%>


function on_init()
{
	sji_docinit(document, cgi);
}

function on_submit()
{
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	return true;
}
</SCRIPT>
</HEAD>

<!-------------------------------------------------------------------------------------->
<!--��ҳ����-->
<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000" onLoad="on_init();">
	<blockquote>
		<DIV align="left" style="padding-left:20px; padding-top:5px">
			<form action=/boaform/admin/formaWifiAudit method=POST name="form">
				<table width="538px" border="0" cellspacing="1" cellpadding="3">
					<tr nowrap>
						<td width="150">��������:</td>
						<td><input type="radio" value="0" name="audit_type" checked>Я��</td>							
					</tr>
					<tr nowrap>
						<td width="150"></td>
						<td><input type="radio" value="1" name="audit_type">�����֤</td>
					</tr>
				</table>
				<input type="submit" class="button" value="ȷ ��" onclick="return on_submit()">
				<input type="hidden" name="submit-url" value="/awifi_audit.asp">
				<input type="hidden" name="postSecurityFlag" value="">
			</form>
		</div>
	</blockquote>
</body>
<%addHttpNoCache();%>
</html>
