<% SendWebHeadStr();%>
<title>Ping <% multilang(LANG_DIAGNOSTICS); %></title>

<SCRIPT>
function goClick()
{
	if (!checkHostIP(document.ping.pingAddr, 1))
		return false;
/*	if (document.ping.pingAddr.value=="") {
		alert("Enter host address !");
		document.ping.pingAddr.focus();
		return false;
	}
	
	return true;*/
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
}
</SCRIPT>
</head>

<body>
<div class="intro_main ">
	<p class="intro_title">Ping <% multilang(LANG_DIAGNOSTICS); %></p>
	<p class="intro_content">  <% multilang(LANG_PAGE_DESC_ICMP_DIAGNOSTIC); %></p>
</div>

<form action=/boaform/formPing method=POST name="ping">
<div class="data_common data_common_notitle">
	<table>
	  <tr>
	      <th width="30%"><% multilang(LANG_HOST_ADDRESS); %>: </th>
	      <td width="70%"><input type="text" name="pingAddr" size="30" maxlength="30"></td>
	  </tr>
	  <tr>
	  	  <th width="30%"><% multilang(LANG_WAN_INTERFACE); %>: </th>
	  	  <td width="70%"><select name="wanif"><% if_wan_list("rt-any-vpn"); %></select></td>
	  </tr>
	</table>
</div>
<div class="btn_ctl">
      <input class="link_bg" type="submit" value=" <% multilang(LANG_GO); %>" onClick="return goClick()">
      <input type="hidden" value="/ping.asp" name="submit-url">
      <input type="hidden" name="postSecurityFlag" value="">
</div>
</form>
<br><br>
</body>
</html>
