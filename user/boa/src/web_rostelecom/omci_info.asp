<html>
<! Copyright (c) Realtek Semiconductor Corp., 2003. All Rights Reserved. ->
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<title><% multilang(LANG_OMCI_INFO); %></title>
<link rel="stylesheet" type="text/css" href="common_style.css" />
<script type="text/javascript" src="share.js">
</script>
<script>

var omci_tm_opt_value = <% getInfo("omci_tm_opt"); %>;
var omcc_ver_value = <% getInfo("omcc_ver"); %>;
var omci_olt_mode_value = <% fmOmciInfo_checkWrite("omci_olt_mode"); %>;

function applyclick()
{
	if (document.formOmciInfo.omci_sw_ver1.value=="") {		
		alert('<% multilang(LANG_OMCI_SW_VER1_CANNOT_BE_EMPTY); %>');
		document.formOmciInfo.omci_sw_ver1.focus();
		return false;
	}
	if (document.formOmciInfo.omci_sw_ver2.value=="") {		
		alert('<% multilang(LANG_OMCI_SW_VER2_CANNOT_BE_EMPTY); %>');
		document.formOmciInfo.omci_sw_ver2.focus();
		return false;
	}
	if (document.formOmciInfo.cwmp_productclass.value=="") {		
		alert('<% multilang(LANG_OMCI_EQID_CANNOT_BE_EMPTY); %>');
		document.formOmciInfo.cwmp_productclass.focus();
		return false;
	}
	if (document.formOmciInfo.cwmp_hw_ver.value=="") {		
		alert('<% multilang(LANG_OMCI_ONT_VER_CANNOT_BE_EMPTY); %>');
		document.formOmciInfo.cwmp_hw_ver.focus();
		return false;
	}

	return true;
}

function on_change()
{
	with (document.forms[0])
	{
		if(omci_olt_mode_value == 0){
			omci_tm_opt.value = omci_tm_opt_value;
			omcc_ver.value = omcc_ver_value;
		}
	}
}

function on_init()
{
	with (document.forms[0])
	{
		omci_tm_opt.value = omci_tm_opt_value;
		omcc_ver.value = omcc_ver_value;
		//if(omci_olt_mode_value == 0)
		//	apply.style.display = "none";
	}
	
}
</script>
</head>

<body onLoad="on_init();">
<blockquote>
<h2 class="page_title"><% multilang(LANG_OMCI_INFO); %></h2>
<form action=/boaform/admin/formOmciInfo method=POST name="formOmciInfo">
<table width=600>
  <tr><td>
  </td></tr>
  <tr><td><hr size=1 noshade align=top></td></tr>
</table>
<table width=600>
<tr>
      <th><% multilang(LANG_OMCI_VENDOR_ID); %></th>
      <td><input type="text" name="omci_vendor_id" size="14" maxlength="4" value="<% getInfo("omci_vendor_id"); %>"></td>
</tr>
<tr>
      <th><% multilang(LANG_OMCI_SW_VER1); %></th>
      <td><input type="text" name="omci_sw_ver1" size="14" maxlength="14" value="<% getInfo("omci_sw_ver1"); %>" <% fmOmciInfo_checkWrite("omci_olt_info_readonly"); %>></td>
</tr>
<tr>
      <th><% multilang(LANG_OMCI_SW_VER2); %></th>
      <td><input type="text" name="omci_sw_ver2" size="14" maxlength="14" value="<% getInfo("omci_sw_ver2"); %>" <% fmOmciInfo_checkWrite("omci_olt_info_readonly"); %>></td>
</tr>
<tr>
      <th><% multilang(LANG_OMCC_VER); %></th>
      <td><!--<input type="text" name="omcc_ver" size="40" maxlength="40" value="<% getInfo("omcc_ver"); %>">-->
      <select name="omcc_ver" <% fmOmciInfo_checkWrite("omci_olt_info_readonly"); %> onChange="on_change()">
      <option value="128" > 0x80</option>
      <option value="129" > 0x81</option>
      <option value="130" > 0x82</option>
      <option value="131" > 0x83</option>
      <option value="132" > 0x84</option>
      <option value="133" > 0x85</option>
      <option value="134" > 0x86</option>
      <option value="150" > 0x96</option>
      <option value="160" > 0xA0</option>
      <option value="161" > 0xA1</option>
      <option value="162" > 0xA2</option>
      <option value="163" > 0xA3</option>
      <option value="176" > 0xB0</option>
      <option value="177" > 0xB1</option>
      <option value="178" > 0xB2</option>
      <option value="179" > 0xB3</option>
      </select></td>
</tr>
<tr>
      <th><% multilang(LANG_OMCI_TM_OPT); %></th>
      <td><!--<input type="text" name="omci_tm_opt" size="40" maxlength="40" value="<% getInfo("omci_tm_opt"); %>">-->
    <select name="omci_tm_opt" <% fmOmciInfo_checkWrite("omci_olt_info_readonly"); %> onChange="on_change()">
	<option value="0" > 0</option>
	<option value="1" > 1 </option>
	<option value="2" > 2 </option>
	</select></td>
</tr>
<tr>
      <th><% multilang(LANG_OMCI_EQID); %></th>
      <td><input type="text" name="cwmp_productclass" size="20" maxlength="20" value="<% getInfo("cwmp_productclass"); %>" <% fmOmciInfo_checkWrite("omci_olt_info_readonly"); %>></td>
</tr>
<tr>
      <th><% multilang(LANG_OMCI_ONT_VER); %></th>
      <td><input type="text" name="cwmp_hw_ver" size="14" maxlength="14" value="<% getInfo("cwmp_hw_ver"); %>" <% fmOmciInfo_checkWrite("omci_olt_info_readonly"); %>></td>
</tr>
</table>
<br>
      <input type="submit" value="<% multilang(LANG_APPLY_CHANGES); %>" name="apply" onClick="return applyclick()">&nbsp;&nbsp;
      <input type="hidden" value="/omci_info.asp" name="submit-url">
</form>
</blockquote>
</body>
</html>
