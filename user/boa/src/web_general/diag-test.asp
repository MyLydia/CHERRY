<% SendWebHeadStr();%>
<title><% multilang(LANG_ADSL_CONNECTION_DIAGNOSTICS); %></title>

<script>
var initInf;

function itfSelected()
{
	initInf = document.diagtest.wan_if.value;
}

function on_submit(obj)
{
	obj.isclick = 1;
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	return true;
}
</script>

<body>
<div class="intro_main ">
	<p class="intro_title"><% multilang(LANG_ADSL_CONNECTION_DIAGNOSTICS); %></p>
	<p class="intro_content"> <% multilang(LANG_THE_DEVICE_IS_CAPABLE_OF_TESTING_YOUR_CONNECTION_THE_INDIVIDUAL_TESTS_ARE_LISTED_BELOW_IF_A_TEST_DISPLAYS_A_FAIL_STATUS_CLICK_GO_BUTTON_AGAIN_TO_MAKE_SURE_THE_FAIL_STATUS_IS_CONSISTENT); %></p>
</div>

<form action=/boaform/formDiagTest method=POST name=diagtest>
<div class="data_common data_common_notitle">
	<table>
		<tr>
			<th width="40%" ><% multilang(LANG_SELECT_THE_ADSL_CONNECTION); %>: </th>
			<td width="30%">
				<select style="width:120px" name="wan_if"  onChange="itfSelected()">
				<% if_wan_list("adsl"); %>
				</select>
			</td>
			<td width="30%"><input type=submit value="<% multilang(LANG_GO); %>" name="start" onClick="return on_submit(this)"></td>
		</tr>
	</table>
</div>
<% lanTest(); %>
<% adslTest(); %>
<% internetTest(); %>
<div class="btn_ctl">
	<input type=hidden value="/diag-test.asp" name="submit-url">
	<input type="hidden" name="postSecurityFlag" value="">
</div>
</form>
<script>
	<% initPage("diagTest"); %>
</script>
<br><br>
</body>
</html>
