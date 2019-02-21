<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<!--系统默认模板-->
<HTML>
<HEAD>
<TITLE>IPv6地址绑定</TITLE>
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
<script type="text/javascript" src="share.js"></script>
<SCRIPT language="javascript" type="text/javascript">

function gotoAddPage()
{
	var i=0;
	window.location.href="net_ipv6_binding_add.asp";	
}

</SCRIPT>
</head>

<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000">
<blockquote>
<DIV align="left" style="padding-left:20px; padding-top:5px">

<form action=/boaform/formIPv6Binding method=POST name="ipv6binding">
<b>IPv6 地址绑定</b>
<table border=1 width="600" cellspacing=4 cellpadding=0>
  <% showIPv6Binding(); %>
</table>
  <br>
  <tr>
   <td>
		<!-- <input type="button" class="btnaddup" value="添加" name="gotoaddV6Route" onclick="window.location.href='/routing_v6_cmcc.asp';">&nbsp;&nbsp; -->
		<input type="button" class="btnaddup" value="添加" name="gotoaddV6Binding" onclick="gotoAddPage();">&nbsp;&nbsp;
		<input type="submit" class="BtnDel" value="删除" name="delV6Binding" >
		<input type="hidden" value="/net_ipv6_binding.asp" name="submit-url">
		&nbsp;&nbsp;
   </td>
  </tr>
  <br>
</form>
</DIV>
</blockquote>
</body>

</html>

