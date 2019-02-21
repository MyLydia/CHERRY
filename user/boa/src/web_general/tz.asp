<% SendWebHeadStr();%>
<title><% multilang(LANG_TIME_ZONE); %><% multilang(LANG_CONFIGURATION); %></title>

<script>
var ntp_zone_index=4;

function ntp_entry(name, value) { 
	this.name = name ;
	this.value = value ;
} 

function setNtpServer(field, ntpServer){
    field.selectedIndex = 0 ;
    for(i=0 ;i < field.options.length ; i++){
    	if(field.options[i].value == ntpServer){
		field.options[i].selected = true;
		break;
	}
    }
}

function checkEmpty(field){
	if(field.value.length == 0){
		alert(field.name + " field can't be empty\n");
		field.value = field.defaultValue;
		field.focus();
		return false;
	}
	else
		return true;
}
function checkNumber(field){
    str =field.value ;
    for (var i=0; i<str.length; i++) {
    	if ( (str.charAt(i) >= '0' && str.charAt(i) <= '9'))
                        continue;
	field.value = field.defaultValue;
        alert("<% multilang(LANG_IT_SHOULD_BE_IN_NUMBER_0_9); %>");
        return false;
    }	
	return true;
}
function checkMonth(str) {
  d = parseInt(str, 10);
  if (d < 0 || d > 12)
      	return false;
  return true;
}
function checkDay(str, month) {
  d = parseInt(str, 10);
  m = parseInt (month, 10);
  if (m == 1 || m == 3 || m == 5 || m == 7 || m == 8 || m == 10 || m == 12) {
  	if (d < 0 || d > 31)
      		return false;
  }
  else if (m == 4 || m == 6 || m == 9 || m == 11) {
  	if (d < 0 || d > 31)
      		return false;
  }
  else if (m == 2) {
  	if (d < 0 || d > 29)
      		return false;
  }
  else
  	return false;
  return true;
}
function checkHour(str) {
  d = parseInt(str, 10);
  if (d < 0 || d >= 24)
      	return false;
  return true;
}
function checkTime(str) {
  d = parseInt(str, 10);
  if (d < 0 || d >= 60)
      	return false;
  return true;
}
function saveChanges(form,obj){
	if((checkEmpty(form.year)& checkEmpty(form.month) & checkEmpty(form.hour)
	 & checkEmpty(form.day) &checkEmpty(form.minute) & checkEmpty(form.second))== false)
	 	return false;

	if((checkNumber(form.year)& checkNumber(form.month) & checkNumber(form.hour)
	 & checkNumber(form.day) &checkNumber(form.minute) & checkNumber(form.second))== false)
	 	return false;
	if(form.month.value == '0'){
		form.month.value = form.month.defaultValue;
        	alert("<% multilang(LANG_INVALID_MONTH_NUMBER_IT_SHOULD_BE_IN_NUMBER_1_9); %>");
		return false;
	}
	if (!checkMonth(form.month.value)) {
		alert("<% multilang(LANG_INVALID_MONTH_SETTING); %>");
		form.month.focus();
		return false;
	}
	if (!checkDay(form.day.value, form.month.value)) {
		alert("<% multilang(LANG_INVALID_DAY_SETTING); %>");
		form.day.focus();
		return false;
	}
	if (!checkHour(form.hour.value)) {
		alert("<% multilang(LANG_INVALID_HOUR_SETTING); %>");
		form.hour.focus();
		return false;
	}
	if (!checkTime(form.minute.value) || !checkTime(form.second.value)) {
		alert("<% multilang(LANG_INVALID_TIME_SETTING); %>");
		return false;
	}
	if (form.enabled.checked && form.ntpServerId[1].checked && form.ntpServerHost2.value != form.ntpServerHost2.defaultValue) {
		if (form.ntpServerHost2.value == "" || !checkString(form.ntpServerHost2.value)) {
			alert("<% multilang(LANG_INVALID_SERVER_STRING); %>");
			form.ntpServerHost2.value = form.ntpServerHost2.defaultValue;
			form.ntpServerHost2.focus();
			return false;
		}
	}	
	obj.isclick = 1;
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	return true;
}
function updateState(form)
{
	if(form.enabled.checked){
		enableTextField(form.ntpServerHost1);
		if(form.ntpServerHost2 != null)
			enableTextField(form.ntpServerHost2);
	}
	else{
		disableTextField(form.ntpServerHost1);
		if(form.ntpServerHost2 != null)
			disableTextField(form.ntpServerHost2);
	}
}
</script>
</head>
<body>
<div class="intro_main ">
	<p class="intro_title"><% multilang(LANG_TIME_ZONE); %> <% multilang(LANG_CONFIGURATION); %></p>
	<p class="intro_content">  <% multilang(LANG_YOU_CAN_MAINTAIN_THE_SYSTEM_TIME_BY_SYNCHRONIZING_WITH_A_PUBLIC_TIME_SERVER_OVER_THE_INTERNET); %></p>
</div>

<form action=/boaform/formNtp method=POST name="time">
<div class="data_common data_common_notitle">
	<table>
		<tr>
			<th width ="25%"> <% multilang(LANG_CURRENT_TIME); %> : </th>
			<td width ="75%">
                <% multilang(LANG_YEAR); %><input type="text" name="year" value="<% getInfo("year"); %>" size="4" maxlength="4">
                <% multilang(LANG_MONTH); %><input type="text" name="month" value="<% getInfo("month"); %>" size="2" maxlength="2">
                <% multilang(LANG_DAY); %><input type="text" name="day" value="<% getInfo("day"); %>" size="2" maxlength="2">
                <% multilang(LANG_HOUR); %><input type="text" name="hour" value="<% getInfo("hour"); %>" size="2" maxlength="2">
                <% multilang(LANG_MIN); %><input type="text" name="minute" value="<% getInfo("minute"); %>" size="2" maxlength="2">
                <% multilang(LANG_SEC); %><input type="text" name="second" value="<% getInfo("second"); %>" size="2" maxlength="2">
	        </td>
		</tr>		
		<tr><th width ="25%"><% multilang(LANG_TIME_ZONE_SELECT); %> : </th>
		    <td width="75%">
	            <select name="timeZone">
		    	<% timeZoneList(); %>
	            </select>
		    </td>
		</tr>	
		<tr><th><% multilang(LANG_ENABLE_DAYLIGHT_SAVING_TIME); %></th>
			<td><input type="checkbox" name="dst_enabled" value="ON">
		    </td>
		</tr>
		<tr><th><% multilang(LANG_ENABLE_SNTP_CLIENT_UPDATE); %></th>
			<td>
				<input type="checkbox" name="enabled" value="ON" ONCLICK=updateState(document.time)>
		    </td>
		</tr>
		<tr>
			<th width="25%"><% multilang(LANG_WAN_INTERFACE); %>:</th>
			<td width="75%">
				<select name="ext_if" <% checkWrite("sntp0d"); %>>
					<option value=65535><% multilang(LANG_ANY); %></option>
					<% if_wan_list("rt"); %>
				</select>
			</td>
		</tr>
		<tr>
			<th width ="25%"> SNTP <% multilang(LANG_SERVER); %> : </th>
			<td width ="75%">
				<input type="radio" value="0" name="ntpServerId"></input>
				<select name="ntpServerHost1">
					<option value="192.5.41.41"><% multilang(LANG_192_5_41_41_NORTH_AMERICA); %></option>
					<option value="192.5.41.209"><% multilang(LANG_192_5_41_209_NORTH_AMERICA); %></option>
					<option value="130.149.17.8"><% multilang(LANG_130_149_17_8_EUROPE); %></option>
					<option value="203.117.180.36"><% multilang(LANG_203_117_180_36_ASIA_PACIFIC); %></option>
				</select>
				&nbsp;&nbsp;&nbsp;&nbsp;
				<input type="radio" value="1" name="ntpServerId"></input>
				<!--ping_zhang:20081217 START:patch from telefonica branch to support WT-107-->
				<input type="text" name="ntpServerHost2" size="15" maxlength="30" value=<% getInfo("ntpServerHost2"); %>> (<% multilang(LANG_MANUAL_SETTING); %>)
			</td>
		</tr>
	</table>
</div>
<div class="adsl clearfix">
	<input type="hidden" value="/tz.asp" name="submit-url">
	<input class="link_bg" type="submit" value="<% multilang(LANG_APPLY_CHANGES); %>" name="save" onClick="return saveChanges(document.time,this)">
	<input class="link_bg" type="button" value="<% multilang(LANG_REFRESH); %>" name="refresh" onClick="javascript: window.location.reload()">
	<input type="hidden" name="postSecurityFlag" value="">
</div>
</form>
<script>
	<% initPage("ntp"); %>
	setNtpServer(document.time.ntpServerHost1, "<% getInfo("ntpServerHost1"); %>");	
	updateState(document.time);

	ifIdx = <% getInfo("ntp-ext-itf"); %>;
	document.time.ext_if.selectedIndex = 0;
	for( i = 1; i < document.time.ext_if.options.length; i++ )
	{
		if( ifIdx == document.time.ext_if.options[i].value )
			document.time.ext_if.selectedIndex = i;
	}
</script>
</body>

</html>
