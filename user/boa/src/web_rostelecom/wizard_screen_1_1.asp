<html>
<! Copyright (c) Realtek Semiconductor Corp., 2003. All Rights Reserved. ->
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<title>Html Wizard</title>
<link href="reset.css" rel="stylesheet" type="text/css" />
<link href="base.css" rel="stylesheet" type="text/css" />
<link href="style.css" rel="stylesheet" type="text/css" />
<script type="text/javascript" src="share.js"></script>

<SCRIPT>
var to_web = 0;
var time_select_val = "322";

<% initWizardScreen1_1(); %>


function saveCheck()
{
 	if (document.Wizard1_1.newpass.value.length == 0)
 	{
  		alert("<% multilang(LANG_PASSWORD_CANNOT_BE_EMPTY); %>");
  		document.Wizard1_1.newpass.focus();
  		return false;
 	}
 	if (document.Wizard1_1.confirmpass.value.length == 0)
 	{
  		alert("<% multilang(LANG_PASSWORD_CANNOT_BE_EMPTY); %>");
  		document.Wizard1_1.confirmpass.focus();
  		return false;
 	}
 	if (document.Wizard1_1.newpass.value != document.Wizard1_1.confirmpass.value)
 	{
  		alert("<% multilang(LANG_PASSWORDS_ARE_NOT_THE_SAME_IF_CONFIRMATION_FIELD_IS_NOT_SAME_PASSWORD); %>");
  		document.Wizard1_1.newpass.focus();
  		return false;
 	}
 	if (checkAdminPasswordValueComplex(document.Wizard1_1.newpass.value) == 0)
 	{
 		alert("<% multilang(LANG_PASSWORD_MUST_CONTAIN_AT_LEAST_1_LETTER_AND_1_DIGIT_AND_SHOULD_BE_NOT_LESS_THAN_6_SYMBOLS); %>");
  		document.Wizard1_1.newpass.focus();
  		return false;
 	}	
 	if (includeSpecialKey(document.Wizard1_1.newpass.value))
 	{
 	 	alert("<% multilang(LANG_INCORRECT_SYMBOL_IF_SYMBOL_FOR_PASSWORD_IS_INCORRECT_OR_CYRILLIC_SYMBOLS_ARE_INSERTED); %>");
  		document.Wizard1_1.newpass.focus();
  		return false;
 	}
 	if (includeCyrillicKey(document.Wizard1_1.newpass.value))
 	{
  		alert("<% multilang(LANG_INCORRECT_SYMBOL_IF_SYMBOL_FOR_PASSWORD_IS_INCORRECT_OR_CYRILLIC_SYMBOLS_ARE_INSERTED); %>");
  		document.Wizard1_1.newpass.focus();
  		return false;
 	}

 	if(to_web)
 	{
 		//top.location.href='/';
		return true;
 	}
 	
 	return true;
}

function init()
{
	var objSelect = document.Wizard1_1.timeZone;
	for (var i = 0; i < objSelect.options.length; i++) {        
        if (objSelect.options[i].value == time_select_val) { 
        	objSelect.options[i].selected = true;        
            break;        
        }        
    }
}

</SCRIPT>
</head>

<body onload="init();">
<div class="data_common data_common_notitle">
<form action=/boaform/admin/formWizardScreen1_1 method=POST name="Wizard1_1">
	<table>
		<tr class="data_prompt_info">
			<td colspan="2"><% multilang(LANG_THIS_ROUTER_IS_IDEAL_FOR_HOME_AND_SMALL_OFFICE_NETWORKS_MASTER_WIZARD_WILL_HELP_YOU_TO_CONFIGURE_INTERNET_CONNECTION); %>
			</td>
		</tr>
		<tr id="userconfirmpass">
			<th width="25%"><% multilang(LANG_TIME_ZONE); %>:</th>
			<th>
				<select name="timeZone">
	    			<OPTION VALUE="365" > <% multilang(LANG_GMT_12_00_KWAJALEIN_ATOLL); %> </OPTION>
					<OPTION VALUE="359" > <% multilang(LANG_GMT_11_00_SAMOA); %> </OPTION>
					<OPTION VALUE="390" > <% multilang(LANG_GMT_10_00_HAWAII); %> </OPTION>
					<OPTION VALUE="185" > <% multilang(LANG_GMT_09_00_ALASKA_); %> </OPTION>
					<OPTION VALUE="385" > <% multilang(LANG_GMT_08_00_MEXICO_PITCAIRN_USA); %> </OPTION>
					<OPTION VALUE="91" > <% multilang(LANG_GMT_07_00_CANADA_MEXICO_UNITED_STATES); %> </OPTION>
					<OPTION VALUE="72" > <% multilang(LANG_GMT_06_00_BELIZE_GUATEMALA_HONDURAS); %>s </OPTION>
					<OPTION VALUE="82" > <% multilang(LANG_GMT_05_00_HAITI_THE_CAYMAN_ISLANDS_CANAD); %> </OPTION>
					<OPTION VALUE="70" > <% multilang(LANG_GMT_04_00_BARBADOS_BOLIVIA_BRAZIL); %> </OPTION>
					<OPTION VALUE="69" > <% multilang(LANG_GMT_03_00_GREENLAND_CANADA_PARAGUAY); %> </OPTION>
					<OPTION VALUE="146" > <% multilang(LANG_GMT_02_00_MID_TIME); %> </OPTION>
					<OPTION VALUE="271" > <% multilang(LANG_GMT_01_00_AZORES_CAPE_VERDE); %> </OPTION>
					<OPTION VALUE="313" > <% multilang(LANG_GMT_LONDON_LISBON_CASABLANCA); %> </OPTION>
					<OPTION VALUE="324" > <% multilang(LANG_GMT_01_00_MADRID_PARIS_ROME); %> </OPTION>
					<OPTION VALUE="311" > <% multilang(LANG_GMT_02_00_KALININGRAD); %> </OPTION>
					<OPTION VALUE="322" > <% multilang(LANG_GMT_03_00_MOSCOW_ST_PETERSBURG_NIZHNY_NOVGOROD); %> </OPTION>
					<OPTION VALUE="329" > <% multilang(LANG_GMT_04_00_SAMARA_IZHEVSK); %> </OPTION>
					<OPTION VALUE="269" > <% multilang(LANG_GMT_05_00_YEKATERINBURG__UFA__PERM__CHELYABINSK__TYUMEN); %> </OPTION>
					<OPTION VALUE="244" > <% multilang(LANG_GMT_06_00_OMSK_NOVOSIBIRSK__BARNAUL__TOMSK); %> </OPTION>
					<OPTION VALUE="233" > <% multilang(LANG_GMT_07_00_KRASNOYARSK__NORILSK__KEMEROVO__ABAKAN__KYZYL); %> </OPTION>
					<OPTION VALUE="224" > <% multilang(LANG_GMT_08_00_IRKUTSK__BRATSK__CHITA__ULAN__UDE); %> </OPTION>
					<OPTION VALUE="268" > <% multilang(LANG_GMT_09_00_YAKUTSK_MIRNY_BLAGOVESHCHENSK); %> </OPTION>
					<OPTION VALUE="267" > <% multilang(LANG_GMT_10_00_VLADIVOSTOK__KHABAROVSK__MAGADAN__YUZHNO__SAKHALINSK); %> </OPTION>
					<OPTION VALUE="190" > <% multilang(LANG_GMT_11_00_SREDNEKOLYMSK__SEVEROKURILSK); %> </OPTION>
					<OPTION VALUE="200" > <% multilang(LANG_GMT_12_00_PETROPAVLOVSK__KAMCHATSKY_ANADYR); %> </OPTION>
            	</select>
			</th>
		</tr>
		
		<tr class="data_prompt_info">
			<td colspan="2"><% multilang(LANG_CHANGE_ROUTER_PASSWORD_FOR_YOUR_SAFETY_ENTER_NEW_PASSWORD_AND_PASSWORD_CONFIRMATION_THEN_PRESS_OK_BUTTON_TO_CONTINUE); %>
			</td>
		</tr>
		<tr id="usernewpass">
			<th width="25%"><% multilang(LANG_NEW_PASSWORD); %>:</th>
			<th>
				<input name="newpass" type="password" size="20" maxlength="30">
			</th>
		</tr>
		<tr id="userconfirmpass">
			<th width="25%"><% multilang(LANG_PASSWORD_CONFIRMATION); %></th>
			<th>
				<input name="confirmpass" type="password" size="20" maxlength="30">
			</th>
		</tr>
	</table>
	<div class="adsl clearfix btn_center">
		<input class="link_bg" type="submit" name="ok" value="<% multilang(LANG_OK); %>" onClick="return saveCheck()" >
		<input type="hidden" value="/admin/web_wizard_4.asp" name="submit-url">
	</div>
</form>
</div>
</body>

</html>
