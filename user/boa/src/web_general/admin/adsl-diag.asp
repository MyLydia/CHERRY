<% SendWebHeadStr();%>
<title><% checkWrite("adsl_diag_title"); %></title>
<script>
function on_submit(obj)
{
	obj.isclick = 1;
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	return true;
}
</script>
</head>

<body>
<div class="intro_main ">
	<p class="intro_title">ADSL Tone Diagnostics</p>
</div>

<form action=/boaform/formDiagAdsl method=POST name=diag_adsl>
<!--<div class="data_common data_common_notitle">-->
<!--this page's style need to modify, when show something, now show nothing-->
<table>
	<tr>
		<td>
			<% checkWrite("adsl_diag_cmt"); %>
		</td>
	</tr>
</table>
<!--</div>-->
<div class="btn_ctl">
	<input class="link_bg" type=submit value="  <% multilang(LANG_START); %>  " name="start" disabled="disabled" onClick="return on_submit(this)">
	<input type=hidden value="/admin/adsl-diag.asp" name="submit-url">
</div>
<% adslToneDiagTbl(); %>

<% vdslBandStatusTbl(); %>

<% adslToneDiagList(); %>
<input type="hidden" name="postSecurityFlag" value="">
<script>
	<% initPage("diagdsl"); %>
</script>										
</form>
<br><br>
</body>
</html>
