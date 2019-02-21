<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<!--系统默认模板-->
<HTML>
<HEAD>
<TITLE>智能诊断系统</TITLE>
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

/********************************************************************
**          on document load
********************************************************************/
function on_submit1()
{
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	return true;
}

function on_submit2()
{
	postTableEncrypt(document.forms[1].postSecurityFlag, document.forms[1]);
	return true;
}
</SCRIPT>
</HEAD>

<!-------------------------------------------------------------------------------------->
<!--主页代码-->
<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000">
	<form id="form" action=/boaform/admin/formAutoDiag method=POST>
		<div align="left" style="padding-left:20px;"><br>
			<div align="left"><b>智能诊断系统</b></div>
			<br>
			<table width="80%" align="left" valign="middle">
			<tr><td>智能诊断系统URL：<input type="text" name="autoDiagURL" <%checkWrite("autoDiagURL");%> maxlength="128" size="50%" disabled /></td></tr>
			<tr><td>当前状态：<%checkWrite("autoDiagEnable");%> </td></tr>
			<tr><td><br><input type="submit" value="停止智能诊断" width="100px" onClick="return on_submit1()" /></td></tr>
			<input type="hidden" name="postSecurityFlag" value="">
			</table>
		</div>
	</form>
	<br><br><br><br><br><br>
	<form id="form" action=/boaform/admin/formQOE method=POST>
		<div align="left" style="padding-left:20px;"><br>
			<div align="left"><b>QOE</b></div>
			<br>
			<table width="80%" align="left" valign="middle">
			<tr><td>QOE URL：<input type="text" name="qoe_url" <%checkWrite("QOE_URL");%> maxlength="128" size="50%" disabled /></td></tr>
			<tr><td>当前状态：<%checkWrite("QOEEnable");%> </td></tr>
			<tr><td><br><input type="submit" value="关闭QOE" width="100px" onClick="return on_submit2()" /></td></tr>
			<input type="hidden" name="postSecurityFlag" value="">
			</table>
		</div>
	</form>
</body>
</html>
