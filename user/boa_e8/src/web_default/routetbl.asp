<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<!--ϵͳĬ��ģ��-->
<HTML>
<HEAD>
<TITLE>·�ɱ�</TITLE>
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
function on_submit()
{
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	return true;
}
</SCRIPT>
</HEAD>

<body>
<blockquote>
<h2><font color="#0000FF">·�ɱ�</font></h2>

<form action=/boaform/formRefleshRouteTbl method=POST name="formRouteTbl">
<table border='1' width="80%">
<% routeList(); %>
</table>

<input type="hidden" value="/routetbl.asp" name="submit-url">
  <p><input type="submit" value="ˢ��" onClick="return on_submit()">&nbsp;&nbsp;
  <input type="button" value="�ر�" name="close" onClick="javascript: window.close();"></p>
  <input type="hidden" name="postSecurityFlag" value="">
</form>
</blockquote>
</body>

</html>
