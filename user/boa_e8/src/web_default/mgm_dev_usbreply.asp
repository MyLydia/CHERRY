<html>
<head>
<meta http-equiv=cache-control content="no-cache, must-revalidate">
<meta http-equiv=content-type content="text/html; charset=gbk">
<meta http-equiv=content-script-type content=text/javascript>
<!--系统公共css-->
<style type=text/css>
@import url(/style/default.css);
</style>
<!--系统公共脚本-->
<script language="javascript" src="common.js"></script>
<script language="javascript" type="text/javascript">
function on_submit()
{
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	return true;
}
</script>
<body>
<form action="/boaform/admin/formUSBbak" method="post">
<table align=center>
<tr align=center>
<td colspan=2 class=actionbuttons >
<input type="hidden" name="forcebackup" value="1">
<input type="submit" value="删除后备份" onClick="return on_submit()"></td>
<td colspan=2 class=actionbuttons><input type='button' onClick='history.back()' value='退出备份'></td>
</tr>
</table>
<input type="hidden" name="postSecurityFlag" value="">
</form>
</body>
<%addHttpNoCache();%>
</html>
