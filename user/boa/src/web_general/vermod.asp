<%SendWebHeadStr(); %>
<title><% multilang(LANG_VERSION); %> </title>

<script>
function sendClicked()
{
        if (document.password.binary.value=="") {
                alert("<% multilang(LANG_SELECTED_FILE_CANNOT_BE_EMPTY); %>");
                document.password.binary.focus();
                return false;
        }

        if (!confirm('<% multilang(LANG_PAGE_DESC_UPGRADE_CONFIRM); %>'))
                return false;
        else
                return true;
}


function uploadClick()
{		
   	if (document.saveConfig.binary.value.length == 0) {
		alert('<% multilang(LANG_CHOOSE_FILE); %>!');
		document.saveConfig.binary.focus();
		return false;
	}
	return true;
}

function exportClick()
{		
   	postTableEncrypt(document.exportOMCIlog.postSecurityFlag, document.exportOMCIlog);
	alert('<% multilang(LANG_PAGE_DESC_WAIT_INFO); %>!');

	return true;
}

function saveChanges()
{
	postTableEncrypt(document.vermod.postSecurityFlag, document.vermod);
	return true;
}
</script>

<STYLE type=text/css>
@import url(/style/default.css);
</STYLE>
</head>

<body>
<DIV align="left" style="padding-left:20px; padding-top:5px">
<div class="intro_main ">
	<p class="intro_title"><% multilang(LANG_VERSION); %></p>
</div>

<form action=/boaform/formVersionMod method=POST name="vermod">
<div class="data_common data_common_notitle">  
	<table>
		<tr>
			<th>Manufacturer:</th>
			<td><input type="text" name="txt_mft" size="50" maxlength="50" value=<% getInfo("rtk_manufacturer"); %>>(ZTE)</td>
		</tr>
		<tr>
			<th>OUI:</th>
			<td><input type="text" name="txt_oui" size="50" maxlength="50" value=<% getInfo("rtk_oui"); %>>(5422F8)</td>
		</tr>
		<tr>
			<th>Product Class:</th>
			<td><input type="text" name="txt_proclass" size="50" maxlength="50" value=<% getInfo("rtk_productclass"); %>>(F660)</td>
		</tr>
		<tr>
			<th>Hardware Serial Number:</th>
			<td><input type="text" name="txt_serialno" size="50" maxlength="50" value=<% getInfo("rtk_serialno"); %>>(000000000002)</td>
		</tr>
		<tr>
			<th>Provisioning Code:</th>
			<td><input type="text" name="txt_provisioningcode" size="50" maxlength="50" value=<% getInfo("cwmp_provisioningcode"); %>>(TLCO.GRP2)</td>
		</tr>
		<tr>
			<th>Spec. <% multilang(LANG_VERSION); %>:</th>
			<td><input type="text" name="txt_specver" size="50" maxlength="50" value=<% getInfo("rtk_specver"); %>>(1.0)</td>
		</tr>
		<tr>
			<th>Software <% multilang(LANG_VERSION); %>:</th>
			<td><input type="text" name="txt_swver" size="50" maxlength="50" value=<% getInfo("rtk_swver"); %>>(V2.30.10P16T2S)</td>
		</tr>
		<tr>
			<th>Hardware <% multilang(LANG_VERSION); %>:</th>
			<td><input type="text" name="txt_hwver" size="50" maxlength="50" value=<% getInfo("rtk_hwver"); %>>(V3.0)</td>
		</tr>
		<tr>
			<th>GPON Serial Number:</th>
			<td><input type="text" name="txt_gponsn" size="13" maxlength="13" value=<% getInfo("gpon_sn"); %>></td>
		</tr>
		<tr>
			<th>ELAN MAC Address:</th>
			<td><input type="text" name="txt_elanmac" size="12" maxlength="12" value=<% getInfo("elan_mac_addr"); %>></td>
		</tr>
	</table>
</div>

<div class="btn_ctl">
	<input class="link_bg" type="submit" value="Save"  onClick="return saveChanges()">&nbsp;&nbsp;
	<!--input type="reset" value="Undo" name="reset" onClick="resetClick()"-->
	<input type="hidden" value="/vermod.asp" name="submit-url">
	<input type="hidden" name="postSecurityFlag" value="">
</div>
</form>
</DIV>
<br>

<DIV align="left" style="padding-left:20px; padding-top:5px">
<div class="intro_main ">
	<p class="intro_title"><% multilang(LANG_FIRMWARE_UPGRADE); %></p>
	<p class="intro_content"> <% multilang(LANG_PAGE_DESC_UPGRADE_FIRMWARE); %></p>
</div>

<form action=/boaform/admin/formUpload method=POST enctype="multipart/form-data" name="password">
<div class="data_common data_common_notitle">
	<table>
		<tr>
			<td><input type="file" value="<% multilang(LANG_CHOOSE_FILE); %>" name="binary" size=20></td>
		</tr>
	</table>
</div>

<div class="btn_ctl">
	<input class="link_bg" type="submit" value="<% multilang(LANG_UPGRADE); %>"  onclick="return sendClicked()">&nbsp;&nbsp;
	<input class="link_bg" type="reset" value="<% multilang(LANG_RESET); %>" name="reset">
</div>
</form>
</DIV>
<br>

<DIV align="left" style="padding-left:20px; padding-top:5px">
<div class="intro_main ">
	<p class="intro_title"><% multilang(LANG_OMCI); %></p>
</div>

<form action=/boaform/formExportOMCIlog method=POST name="exportOMCIlog">
<div class="data_common data_common_notitle">
	<table>
		<tr>
			<th width=60%><% multilang(LANG_EXPORT); %>:</th>
			<td>
				<input class="inner_btn" type="submit" value="<% multilang(LANG_EXPORT); %>"  onclick="return exportClick()">
				<input type="hidden" name="postSecurityFlag" value="">
			</td>
		</tr>
	</table>
</div>
</form>
</DIV>


<DIV align="left" style="padding-left:20px; padding-top:5px">
<form action=/boaform/formImportOMCIShell enctype="multipart/form-data" method=POST name="saveConfig">
<div class="data_common data_common_notitle">
	<table>
		<tr>
			<th width=30%><% multilang(LANG_IMPORT); %>:</th>
			<td width=30%><input class="inner_btn" type="file" value="<% multilang(LANG_CHOOSE_FILE); %>" name="binary" size=24></td>
			<td><input class="inner_btn" type="submit" value="<% multilang(LANG_IMPORT); %>" name="load" onclick="return uploadClick()"></td>
		</tr>  
	</table>
</div>
</form> 

</DIV>
</blockquote>

</body>

</html>
