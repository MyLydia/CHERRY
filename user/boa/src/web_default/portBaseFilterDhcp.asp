<html>
<! Copyright (c) Realtek Semiconductor Corp., 2003. All Rights Reserved. ->
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<title><% multilang(LANG_PORT_BASED_FILTER); %></title>
<link rel="stylesheet" type="text/css" href="common_style.css" />
<script type="text/javascript" src="share.js">
</script>
<SCRIPT language="javascript" src="/common.js"></SCRIPT>
<SCRIPT>
function saveChanges()
{
	var ptmap = 0;
	var pmchkpt = document.getElementById("tbl_pmap");

	if (pmchkpt) {
		with (document.forms[0]) {
			for(var i = 0; i < 14; i ++) {
				if (!chkpt[i])
					continue;
				if(chkpt[i].checked == true) ptmap |= (0x1 << i);
			}
			dhcpPortFilter.value = ptmap;
		}
	}

	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	
	return true;
}

function on_init()
{
	return true;
}
</SCRIPT>
</head>


<body onLoad="on_init();">
<blockquote>
<h2 class="page_title"><% multilang(LANG_PORT_BASED_FILTER); %></h2>

<table >
  <tr><td><font size=2>
  <% multilang(LANG_PAGE_DESC_CONFIGURE_PORT_BASED_FILTERING); %>
  </font></td></tr>
  <tr><td><hr size=1 noshade align=top></td></tr>
</table>

<form action=/boaform/formmacBase method=POST name="stbIp">
	<% ShowPortBaseFiltering(); %>	
	<input type="submit" value="<% multilang(LANG_APPLY_CHANGES); %>"  onClick="return saveChanges()">&nbsp;&nbsp;
	<input type="hidden" value="/portBaseFilterDhcp.asp" name="submit-url">
	<input type="hidden" name="dhcpPortFilter" value=0>
	<input type="button" value="<% multilang(LANG_CLOSE); %>" name="close" onClick="javascript: window.close();">
	<input type="hidden" name="postSecurityFlag" value="">

<script>
	var mode = <% getInfo("dhcp_port_filter"); %>;	
	var pmchkpt = document.getElementById("tbl_pmap");
	with ( document.forms[0] )
	{
		//port mapping
		if (pmchkpt)
			for(var i = 0; i < 14; i ++) {
				if (!chkpt[i])
					continue;
				chkpt[i].checked = (mode & (0x1 << i));
			}
	}
</script>

</form>
</blockquote>
</body>

</html>
