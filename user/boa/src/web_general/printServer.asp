<% SendWebHeadStr();%>
<meta http-equiv="refresh" content="10">
<title><% multilang(LANG_PRINTER); %> URL(s)</title>
<script>
</script>
</head>

<body>
<div class="intro_main ">
	<p class="intro_title"><% multilang(LANG_PRINTER); %> URL(s)</p>
	<p class="intro_content"> <% multilang(LANG_THIS_PAGE_IS_USED_TO_SHOW_PRINTER_URL_S); %></p>
</div>

<div class="intro_main ">	
	<p class="intro_content">
		<% printerList(); %>
	</p>	
</div>
<div class="btn_ctl">
	<input class="link_bg" type="button" value="<% multilang(LANG_REFRESH); %>" name="refresh" onClick="location.reload();">
</div>
</body>
</html>
