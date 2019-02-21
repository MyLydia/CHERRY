<!DOCTYPE html>
<html>
<head>
<meta http-equiv="Content-Type" content="text/html" charset="arial">
<meta http-equiv = 'refresh' content = '2;url=tracert6_result.asp' >
<link rel="stylesheet" href="/admin/reset.css">
<link rel="stylesheet" href="/admin/base.css">
<link rel="stylesheet" href="/admin/style.css">
<script type="text/javascript" src="share.js"></script>
<title>Tracert <% multilang(LANG_DIAGNOSTICS); %></title>
</head>

<body>
<div class="intro_main ">
	<p class="intro_title">Traceroute6 <% multilang_old("Result:"); %></p>
</div>
<br>
<div align="left">
	<table border=0 id="traceInfo" width="600" cellspacing=4 cellpadding=0>
		<% dumpTraceInfo(); %>
	</table>
	<br>
	<table>
		<tr><td>
			<input class="link_bg" type="button" value="back" name="back" onclick="window.location.replace('/tracert6.asp')" />
		</td></tr>
	</table>
</div>
<br><br>
</body>
</html>
