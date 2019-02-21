<%SendWebHeadStr(); %>
<title><% multilang(LANG_ACTIVE_DHCP_CLIENTS); %></title>
<!--<link rel="stylesheet" href="admin/content.css">-->
</head>

<body>
<div class="intro_main ">
	<p class="intro_title"><% multilang(LANG_INITIATING_END_SCRIPT_CONTENT); %></p>
</div>

<table>
  <tr><td>
	<% checkWrite("getEndScriptContent"); %>
  </td></tr>
</table>
<br><br>
</body>

</html>

