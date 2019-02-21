<%SendWebHeadStr(); %>
<title><% multilang(LANG_PORT_BASED_FILTER); %></title>

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
<div class="intro_main ">
	<p class="intro_title"><% multilang(LANG_PORT_BASED_FILTER); %></p>
	<p class="intro_content"> <% multilang(LANG_PAGE_DESC_CONFIGURE_PORT_BASED_FILTERING); %></p>
</div>

<form action=/boaform/formmacBase method=POST name="stbIp">
	<% ShowPortBaseFiltering(); %>	
<div class="btn_ctl">
	<input class="link_bg" type="submit" value="<% multilang(LANG_APPLY_CHANGES); %>"  onClick="return saveChanges()">&nbsp;&nbsp;
	<input type="hidden" value="/portBaseFilterDhcp.asp" name="submit-url">
	<input type="hidden" name="dhcpPortFilter" value=0>
	<input class="link_bg" type="button" value="<% multilang(LANG_CLOSE); %>" name="close" onClick="javascript: window.close();">
	<input type="hidden" name="postSecurityFlag" value="">
</div>

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
</body>
</html>
