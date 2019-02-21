<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<!--系统默认模板-->
<HTML>
<HEAD>
<TITLE>IGMP Snooping 配置</TITLE>
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
/*
var cgi = new Object();
<%initPageIgmpSnooping();%>
*/

/********************************************************************
**          on document load
********************************************************************/
function on_init()
{
	sji_docinit(document, cgi);
}

function proxySelection()
{
	if(!document.igmpMldProxy.chkIgmpMldProxy.checked)
	{
		document.igmpMldProxy.ext_if.disabled = true;
	}
	else
	{
		document.igmpMldProxy.ext_if.disabled = false;
	}
}

function on_apply(form)
{
	if(form==0)
	{
		if(document.getElementById("chkIgmpMldSnp").checked==true)
			document.getElementById("snp").value=1;
		else
			document.getElementById("snp").value=0;
		document.getElementById("formSnooping").submit();
	}
	if(form==1)
	{
		if(document.getElementById("chkIgmpMldProxy").checked==true)
			document.getElementById("proxy").value=1;
		else
			document.getElementById("proxy").value=0;
		document.getElementById("formProxy").submit();
	}
}
</SCRIPT>
</HEAD>

<!-------------------------------------------------------------------------------------->
<!--主页代码-->
<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000">
	<blockquote>
		<DIV align="left" style="padding-left:20px; padding-top:5px">
			<form id="formSnooping" action=/boaform/formIgmpMldSnooping method=POST name="igmpMldSnoop">
				<b></b><br><br>
				<br><br>
				<table border=0 width="500" cellspacing=4 cellpadding=0>
					<tr>
					<td width=200>启用IGMP/MLD Snooping:</td>
						<td>
						<input type="checkbox" id="chkIgmpMldSnp"></td>
				</tr></table>
				<br>
				<center><button class="btnsaveup" name="apply" onclick="on_apply(0)">应用</button></center>
				<input type="hidden" id="snp" name="snp">
				<input type="hidden" name="submit-url" value="/snooping_proxy_cmcc.asp">
			<script>
				<% initPage("igmpMldSnooping"); %>	
			</script>			
			</form>
		</DIV>
		
		<br><br>
		<DIV align="left" style="padding-left:20px; padding-top:5px">
			<form id="formProxy" action=/boaform/formIgmpMldProxy method=POST name="igmpMldProxy">
				<b></b><br><br>
				<br><br>
				<table border=0 width="500" cellspacing=4 cellpadding=0>
					<tr>
					<td width=200>启用IGMP/MLD Proxy:</td>
					<td><input type="checkbox" id="chkIgmpMldProxy"></td>
				</tr>
				</table>
				<br>
				<table border=0 width="500" cellspacing=4 cellpadding=0>
					<td>WAN接口:&nbsp;</td>				
					<td> <select name="ext_if" <%checkWrite("mldproxy0dcmcc"); %>> <% if_wan_list("rtInternetOther"); %> </select> </td>
				</table>
				<center><button class="btnsaveup" name="apply" onclick="on_apply(1)">应用</button> </center>
				<input type="hidden" id="proxy" name="proxy">
				<input type="hidden" name="submit-url" value="/snooping_proxy_cmcc.asp">
			<script>
				<% initPage("igmpMldProxy"); %>	
			</script>			
			</form>
		</DIV>
	</blockquote>
<script>
	//initUpnpDisable = document.igmpMldProxy.chkIgmpMldProxy.checked;

	ifIdx = <% getInfo("mldproxy-ext-itf"); %>;
	if (ifIdx != 65535)
		document.igmpMldProxy.ext_if.value = ifIdx;
	else
		document.igmpMldProxy.ext_if.selectedIndex = 0;

	proxySelection();
</script>
</body>
<%addHttpNoCache();%>
</html>
