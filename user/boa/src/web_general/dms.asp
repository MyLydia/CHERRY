<% SendWebHeadStr();%>
<title><% multilang(LANG_DIGITAL_MEDIA_SERVER_SETTINGS); %></title>

<script>
function dmsSelection()
{
	return true;
}

function on_submit()
{
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	return true;
}
</script>
</head>

<body>
<div class="intro_main ">
	<p class="intro_title"><% multilang(LANG_DIGITAL_MEDIA_SERVER_SETTINGS); %></p>
	<p class="intro_content"><% multilang(LANG_THIS_PAGE_IS_USED_TO_CONFIGURE_THE_PARAMETERS_FOR_YOUR_DIGITAL_MEDIA_SERVER); %></p>
</div>
<form action=/boaform/formDMSConf method=POST name="formDMSconf">
	<div class="data_common data_common_notitle">
		<table>
		  <tr>
		      <th width="40%"><% multilang(LANG_DIGITAL_MEDIA_SERVER); %>:</th>
		      <td width="60%">
			      <input type="radio" name="enableDMS" value=0 <% fmDMS_checkWrite("fmDMS-enable-dis"); %> onClick="dmsSelection()" ><% multilang(LANG_DISABLE); %>&nbsp;&nbsp;
			      <input type="radio" name="enableDMS" value=1 <% fmDMS_checkWrite("fmDMS-enable-en"); %>  onClick="dmsSelection()" ><% multilang(LANG_ENABLE); %>
		      </td>
		  </tr>  
		</table>
	</div>
	<div class="btn_ctl">
	      <input type="submit" value="<% multilang(LANG_APPLY_CHANGES); %>" class="link_bg" onClick="return on_submit()">&nbsp;&nbsp;
	      <!--<input type="reset" value="Undo" name="reset" onClick="window.location.reload()">-->
	      <input type="hidden" value="/dms.asp" name="submit-url">
	</div>
</form>
<br><br>
</body>
</html>
