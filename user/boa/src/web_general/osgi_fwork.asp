<%SendWebHeadStr(); %>
<title><% multilang(LANG_FRAMEWORK_INFO); %></title>

</head>
<body>
<div class="intro_main ">
	<p class="intro_title"><% multilang(LANG_FRAMEWORK_INFO); %></p>
	<p class="intro_content"> <% multilang(LANG_THIS_PAGE_SHOWS_THE_OSGI_FRAMWEORK_OF_THE_DEVICE); %></p>
</div>

<form action=/boaform/admin/formStatus method=POST name="status2">
<div class="column">
	<div class="column_title">
		<div class="column_title_left"></div>
			<p><% multilang(LANG_OSGI_FRAMEWORK_INFORMATION); %></p>
		<div class="column_title_right"></div>
	</div>
	<div class="data_common">
		<table>
			<tr>
				<th width=30%><% multilang(LANG_FRAMEWORK_NAME); %></th>
				<td><% getOSGIInfo("fwname"); %></td>
			</tr>
			<tr>
				<th><% multilang(LANG_FRAMEWORK_VERSION); %></th>
				<td><% getOSGIInfo("fwver"); %></td>
			</tr>
			<tr>
				<th><% multilang(LANG_FRAMEWORK_STATUS); %></th>
				<td><% getOSGIInfo("fwstatus"); %></td>
			</tr>
		</table>
	</div>
</div>

<% getOSGIBundleList("0"); %>
</form>
</body>
</html>
