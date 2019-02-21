<%SendWebHeadStr(); %>
<title><% multilang(LANG_OMCI_INFO); %></title>

<script>

var omci_vendor_id_value = "<% getInfo("omci_vendor_id"); %>";
var omci_sw_ver1_value = "<% getInfo("omci_sw_ver1"); %>";
var omci_sw_ver2_value = "<% getInfo("omci_sw_ver2"); %>";
var omci_tm_opt_value = <% getInfo("omci_tm_opt"); %>;
var omcc_ver_value = <% getInfo("omcc_ver"); %>;
var cwmp_productclass_value = "<% getInfo("cwmp_productclass"); %>";
var cwmp_hw_ver_value = "<% getInfo("cwmp_hw_ver"); %>";
var omci_olt_mode_value = <% fmOmciInfo_checkWrite("omci_olt_mode"); %>;

function applyclick(obj)
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

	obj.isclick = 1;
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	
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
		omci_vendor_id.value = omci_vendor_id_value;
		omci_sw_ver1.value = omci_sw_ver1_value;
		omci_sw_ver2.value = omci_sw_ver2_value;
		omci_tm_opt.value = omci_tm_opt_value;
		omcc_ver.value = omcc_ver_value;
		cwmp_productclass.value = cwmp_productclass_value;
		cwmp_hw_ver.value = cwmp_hw_ver_value;
		//if(omci_olt_mode_value == 0)
		//	apply.style.display = "none";
		if(omci_olt_mode_value == 0)
		{
			get_by_id("omci_sw_ver1_text").innerHTML = omci_sw_ver1_value;
			get_by_id("omci_sw_ver1_text").style.display = "";
			get_by_id("omci_sw_ver2_text").innerHTML = omci_sw_ver2_value;
			get_by_id("omci_sw_ver2_text").style.display = "";
			get_by_id("omcc_ver_text").innerHTML =  "0x" + omcc_ver_value.toString(16);
			get_by_id("omcc_ver_text").style.display = "";
			get_by_id("omci_tm_opt_text").innerHTML =  omci_tm_opt_value;
			get_by_id("omci_tm_opt_text").style.display = "";
			get_by_id("cwmp_productclass_text").innerHTML = cwmp_productclass_value;
			get_by_id("cwmp_productclass_text").style.display = "";
			get_by_id("cwmp_hw_ver_text").innerHTML = cwmp_hw_ver_value;
			get_by_id("cwmp_hw_ver_text").style.display = "";

			disableTextField(document.forms[0].omci_sw_ver1);
			disableTextField(document.forms[0].omci_sw_ver2);
			disableTextField(document.forms[0].omci_tm_opt);
			disableTextField(document.forms[0].omcc_ver);
			disableTextField(document.forms[0].cwmp_productclass);
			disableTextField(document.forms[0].cwmp_hw_ver);
		}
		else
		{
			get_by_id("omci_sw_ver1_input").style.display = "";
			get_by_id("omci_sw_ver2_input").style.display = "";
			get_by_id("omcc_ver_selection").style.display = "";
			get_by_id("omci_tm_opt_selection").style.display = "";
			get_by_id("cwmp_productclass_input").style.display = "";
			get_by_id("cwmp_hw_ver_input").style.display = "";
		}
			
	}
	
}
</script>
</head>

<body onLoad="on_init();">
<div class="intro_main ">
	<p class="intro_title"><% multilang(LANG_OMCI_INFO); %></p>
</div>

<form action=/boaform/admin/formOmciInfo method=POST name="formOmciInfo">

<div class="data_common data_common_notitle">
<table>
	<tr>
		<th><% multilang(LANG_OMCI_VENDOR_ID); %>:</th>
		<td><input type="text" name="omci_vendor_id" size="14" maxlength="4"></td>
	</tr>
	<tr>
		<th><% multilang(LANG_OMCI_SW_VER1); %>:</th>
		<td>
		<div id="omci_sw_ver1_text" style="display:none"> </div>
		<div id="omci_sw_ver1_input" style="display:none">
		<input type="text" name="omci_sw_ver1" size="14" maxlength="14">
		</div>
		</td>
	</tr>
	<tr>
		<th><% multilang(LANG_OMCI_SW_VER2); %>:</th>
		<td>
		<div id="omci_sw_ver2_text" style="display:none"> </div>
		<div id="omci_sw_ver2_input" style="display:none">
		<input type="text" name="omci_sw_ver2" size="14" maxlength="14"></td>
		</div>
	</tr>
	<tr>
		<th><% multilang(LANG_OMCC_VER); %>:</th>
		<td><!--<input type="text" name="omcc_ver" size="40" maxlength="40" value="<% getInfo("omcc_ver"); %>">-->
		<div id="omcc_ver_text" style="display:none"> </div>
		<div id="omcc_ver_selection" style="display:none">
			<select name="omcc_ver" onChange="on_change()">
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
			</select>
		</div>
		</td>
	</tr>
	<tr>
		<th><% multilang(LANG_OMCI_TM_OPT); %>:</th>
		<td><!--<input type="text" name="omci_tm_opt" size="40" maxlength="40" value="<% getInfo("omci_tm_opt"); %>">-->
		<div id="omci_tm_opt_text" style="display:none"> </div>
		<div id="omci_tm_opt_selection" style="display:none">
			<select name="omci_tm_opt" onChange="on_change()">
			<option value="0" > 0</option>
			<option value="1" > 1 </option>
			<option value="2" > 2 </option>
			</select>
		</div>
		</td>
	</tr>
	<tr>
		<th><% multilang(LANG_OMCI_EQID); %>:</th>
		<td>
		<div id="cwmp_productclass_text" style="display:none"></div>
		<div id="cwmp_productclass_input" style="display:none">
		<input type="text" name="cwmp_productclass" size="20" maxlength="20">
		</div>
		</td>
	</tr>
	<tr>
		<th><% multilang(LANG_OMCI_ONT_VER); %>:</th>
		<td>
		<div id="cwmp_hw_ver_text" style="display:none"></div>
		<div id="cwmp_hw_ver_input" style="display:none">
		<input type="text" name="cwmp_hw_ver" size="14" maxlength="14"></td>
		</div>
	</tr>
</table>
</div>

<div class="btn_ctl">
      <input class="link_bg" type="submit" value="<% multilang(LANG_APPLY_CHANGES); %>" name="apply" onClick="return applyclick(this)">&nbsp;&nbsp;
      <input type="hidden" value="/omci_info.asp" name="submit-url">
      <input type="hidden" name="postSecurityFlag" value="">
</div>
</form>
</body>
</html>
