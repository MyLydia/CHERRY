<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<!--系统默认模板-->
<HTML>
<HEAD>
<TITLE>广域网访问设置</TITLE>
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
var cgi = new Object();
/********************************************************************
**          on document load
********************************************************************/
function proxySelection()
{
	if(document.upnp.daemon.checked)
	{
		document.upnp.ext_if.disabled = true;
	}
	else
	{
		document.upnp.ext_if.disabled = false;
	}
}

function checkChange(cb)
{
	if(cb.checked==true){
		cb.value = 1;
	}
	else{
		cb.value = 0;
	}
}

</script>

</SCRIPT>
</HEAD>

<!-------------------------------------------------------------------------------------->
<!--主页代码-->
<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000" onLoad="">
  <blockquote>
	<DIV align="left" style="padding-left:20px; padding-top:5px">
		<form id="form" action=/boaform/admin/formUpnp method=POST name="upnp">
			<br>
			<table border="0" cellpadding="0" cellspacing="0">
			  <tr>
			  	<td>启用UPnP:</td>
				<td>
					<input type="checkbox" name="daemon" onChange="checkChange(this)" <% checkWrite("upnp_enable"); %>>
			  </tr>
			</table>
			<DIV name="div_wanif" style="display:none;">
			<table border="0" cellpadding="0" cellspacing="0">
			  <tr>
			  	<td>WAN Interface:&nbsp;</td>
				<td> <select name="ext_if"> <% if_wan_list("rtInternet"); %> </select> </td>
			  </tr>
			</table>
			</DIV>
			<br><br>
			<div align="center">
				<img id="btnOK" name="save" onclick="submit()" src="/image/ok_cmcc.gif" border="0">&nbsp;&nbsp;
				<img id="btnCancel" onclick="window.location.reload()" src="/image/cancel_cmcc.gif" border="0">
				<input type="hidden" value="/app_upnp_cmcc.asp" name="submit-url">
			</div>
		</form>
	</DIV>
  </blockquote>

<script>
	document.upnp.ext_if.selectedIndex = 0;

	proxySelection();
</script>
</body>
<%addHttpNoCache();%>
</html>
