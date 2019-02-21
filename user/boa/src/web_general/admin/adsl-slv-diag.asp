<%SendWebHeadStr(); %>
<title><% checkWrite("adsl_slv_diag_title"); %></title>
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
	<p class="intro_title"><% checkWrite("adsl_slv_diag_title"); %></p>
	<p class="intro_content"> <% checkWrite("adsl_slv_diag_cmt"); %></p>
</div>

<form action=/boaform/formDiagAdsl method=POST name=diag_adsl>
<div class="btn_ctl">
	<input class="link_bg" type=submit value="  <% multilang(LANG_START); %>  " name=start disabled="disabled" onClick="return on_submit(this)">
	<input type=hidden value="/admin/adsl-slv-diag.asp" name="submit-url">
	<input type=hidden value="1" name="slaveid">
</div>

<% adslToneDiagTbl("1"); %>

<% vdslBandStatusTbl("1"); %>

<% adslToneDiagList("1"); %>
<input type="hidden" name="postSecurityFlag" value="">
<script>
	<% initPage("diagdslslv"); %>
</script>
</form>
<br><br>
</body>

</html>
