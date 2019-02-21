<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<!--系统默认模板-->
<HTML>
<HEAD>
<TITLE>路由表</TITLE>
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
function on_submit()
{
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	return true;
}
</SCRIPT>
</HEAD>

<body>
<blockquote>
<h2><font color="#0000FF">路由表</font></h2>

<form action=/boaform/formRefleshRouteTbl method=POST name="formRouteTbl">
<table border='1' width="80%">
<% routeList(); %>
</table>

<input type="hidden" value="/routetbl.asp" name="submit-url">
  <p><input type="submit" value="刷新" onClick="return on_submit()">&nbsp;&nbsp;
  <input type="button" value="关闭" name="close" onClick="javascript: window.close();"></p>
  <input type="hidden" name="postSecurityFlag" value="">
</form>
</blockquote>
</body>

</html>
