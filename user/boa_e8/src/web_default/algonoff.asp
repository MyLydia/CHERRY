<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<!--系统默认模板-->
<HTML>
<HEAD>
<TITLE>ALG On-Off</TITLE>
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
function AlgTypeStatus()
{
	<%checkWrite("AlgTypeStatus");%>
	return true;
}
function on_submit()
{
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	return true;
}
</SCRIPT>
</head>

<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000">
<blockquote>
<DIV align="left" style="padding-left:20px; padding-top:5px">

<form action=/boaform/formALGOnOff method=POST name=algof>
<table  width=500>
<tr><td colspan=4><hr size=1 noshade align=top></td></tr>
<div class="tip" style="width:90% ">
	<b>ALG配置</b><br><br>	
</div>
<table>
<tr>
<td>选择下面的ALG:</td>
<td colspan="2">	
</td>
</tr>
<%checkWrite("GetAlgType")%>	
<tr>
	<td ><input type="submit" value="保存/应用"  onClick="return on_submit()"></td>
  <td> <input type="hidden" value="/algonoff.asp" name="submit-url"></td>
  <td><input type="hidden" name="postSecurityFlag" value=""></td>
</tr>
</table>
</table>
</form>
<script>
AlgTypeStatus();
</script>
</DIV>
</blockquote>
</body>
</html>
