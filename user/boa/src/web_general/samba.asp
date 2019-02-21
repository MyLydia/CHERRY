<% SendWebHeadStr();%>
<title>Samba<% multilang(LANG_CONFIGURATION); %></title>
<script language="javascript">
var nbn = "<% getInfo("samba-netbios-name"); %>";
var ss = "<% getInfo("samba-server-string"); %>";

function changeSambaCap()
{
	with (document.formSamba) {
		if (sambaCap[0].checked) {
			/* Disable */
			netBIOSName.value = "";
			serverString.value = "";
			changeBlockState("conf", true);
		} else {
			/* Enable */
			netBIOSName.value = nbn;
			serverString.value = ss;
			changeBlockState("conf", false);
		}
	}
}

function on_submit()
{
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	return true;
}
</script>
</head>

<body onLoad="changeSambaCap();">
<div class="intro_main ">
	<p class="intro_title">Samba</p>
	<p class="intro_content"><% multilang(LANG_THIS_PAGE_LET_USER_TO_CONFIG_SAMBA); %></p>
</div>
<form action=/boaform/formSamba method=post name="formSamba">

<div class="data_common data_common_notitle">
	<table>
		<tr>
			<th width=40%>Samba:</th>
			<td width=60%>
				<input type="radio" value="0" name="sambaCap" onClick="changeSambaCap();" <% checkWrite("samba-cap0"); %>><% multilang(LANG_DISABLE); %>&nbsp;&nbsp;
				<input type="radio" value="1" name="sambaCap" onClick="changeSambaCap();" <% checkWrite("samba-cap1"); %>><% multilang(LANG_ENABLE); %>
			</td>
		</tr>
		<% checkWrite("smbSecurity"); %>
		<tbody id="conf">
			<tr <% checkWrite("nmbd-cap"); %>>
				<th width=40%>NetBIOS <% multilang(LANG_NAME); %>&nbsp;:</td>
				<td width=60%><input type="text" name="netBIOSName" maxlength="15"><td>
			</tr>
			<tr>
				<th width=40%><% multilang(LANG_SERVER_STRING); %>&nbsp;:</td>
				<td width=60%><input type="text" name="serverString" maxlength="31"></td>
			</tr>
		</tbody>
	</table>
</div>
<div class="btn_ctl">
	<input class="link_bg" type="submit" value="<% multilang(LANG_APPLY_CHANGES); %>" onClick="return on_submit()">&nbsp;&nbsp;
	<input type="hidden" value="/samba.asp" name="submit-url"> 
	<input type="hidden" name="postSecurityFlag" value="">
</div>
</form>
<br><br>
</body>
</html>
