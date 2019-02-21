<%SendWebHeadStr(); %>
<title><% multilang(LANG_ETHERNET_LINK_SPEED_DUPLEX_MODE); %></title>

<SCRIPT>
function postit(port, pvc)
{
	switch(port) {
	case 0:
		if (pvc != 255)
			document.eth2pvc.vc0.value = pvc;
		else
			document.eth2pvc.vc0.selectedIndex = 0;
		break;
	case 1:
		if (pvc != 255)
			document.eth2pvc.vc1.value = pvc;
		else
			document.eth2pvc.vc1.selectedIndex = 0;
		break;
	case 2:
		if (pvc != 255)
			document.eth2pvc.vc2.value = pvc;
		else
			document.eth2pvc.vc2.selectedIndex = 0;
		break;
	case 3:
		if (pvc != 255)
			document.eth2pvc.vc3.value = pvc;
		else
			document.eth2pvc.vc3.selectedIndex = 0;
	default: break;
	}
}

function linkOption()
{
	document.write('<option value=0>10M <% multilang(LANG_HALF_MODE); %></option>\n');
	document.write('<option value=1>10M <% multilang(LANG_FULL_MODE); %></option>\n');
	document.write('<option value=2>100M <% multilang(LANG_HALF_MODE); %></option>\n');
	document.write('<option value=3>100M <% multilang(LANG_FULL_MODE); %></option>\n');
	document.write('<option value=4><% multilang(LANG_AUTO_MODE); %></option>\n');
}

function on_submit(obj)
{
	obj.isclick = 1;
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	return true;
}	
</SCRIPT>
</head>

<body>
<div class="intro_main ">
	<p class="intro_title"><% multilang(LANG_ETHERNET_LINK_SPEED_DUPLEX_MODE); %></p>
	<p class="intro_content"> <% multilang(LANG_SET_THE_ETHERNET_LINK_SPEED_DUPLEX_MODE); %></p>
</div>

<form action=/boaform/formLinkMode method=POST name=link>
<div class="data_common data_common_notitle">
	<table>
	  <tr>
	      <th>eth0:</th>
	      <td>
	      	<select name=p0>
	      		<script>
	      			linkOption();
	      		</script>
	      	</select>
	      </td>
	  </tr>
	</table>
</div>

<div class="btn_ctl">
      <input class="link_bg" type="submit" value="<% multilang(LANG_APPLY_CHANGES); %>" name="save" onClick="return on_submit(this)">&nbsp;&nbsp;
      <input type="hidden" value="/linkmode_eth.asp" name="submit-url">
      <input type="hidden" name="postSecurityFlag" value="">
</div>
<script>
	<% initPage("linkMode"); %>
</script>
</form>
</body>

</html>
