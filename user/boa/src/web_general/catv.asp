<%SendWebHeadStr(); %>
<title>CATV</title>
<head>
<script type="text/javascript">
function WebDoSubmit()
{
        var RF_att_set=$("RF_att_set").value;
        var RF_switch=$("RF_switch").value;

        if(RF_att_set=="N/A" || RF_switch=="N/A")
        {
                alert("The value can not be  N/A, please set again!");
				//javascript: window.location.reload()
                return false;
        }
        $("formCatv").submit();
}

function WebInit()
{

var  RF_switch_get ="<%fmcatv_checkWrite("RF_switch");%>";
	 console.log('RF_switch_get='+ RF_switch_get);
	 
	 if(RF_switch_get != "0")
	 {
		RF_switch.value= "1";
	 }
	 else 
		RF_switch.value= RF_switch_get;

var RF_att_set_get = "<%fmcatv_checkWrite("RF_att_set");%>";
	console.log('RF_att_set_get=',RF_att_set_get);
	RF_att_set.value=RF_att_set_get; 
	 
}
</script>
</head>
<body onload="WebInit();">
<div>
 <p class="intro_title"> CATV SETTING </p>
 <p class="intro_content">catv setting information </p>
</div>
<!-- <center> -->
<form id="formCatv" action=/boaform/admin/formCatv method=GET name="formeponconf">
<input type=hidden name=voipPort value="<%fmcatv_checkWrite("uart_read");%>">
<div class="data_common data_common_notitle">
<table>
 <tr>
  <th width="40%">name</th>
  <td><input type="text" name="dev_name" size="20" maxlength="20" value="<% fmcatv_checkWrite("dev_name"); %>" readonly="true" disabled></td>
 </tr>
 <tr>
  <th width="40%">work state</th>
  <td><input type="text" name="state" size="20" maxlength="12" value="<% fmcatv_checkWrite("state"); %>" readonly="true" disabled></td>
 </tr>
 <tr>
  <th width="40%">receive power</th>
  <td><input type="text" name="receive_power" size="20" maxlength="12" value="<% fmcatv_checkWrite("receive_power"); %>" readonly="true" disabled></td>
 </tr>
 
 <tr>
  <th width="40%">transmit power</th>
  <td><input type="text" name="transmit_power" size="20" maxlength="12" value="<% fmcatv_checkWrite("transmit_power"); %>" readonly="true" disabled></td>
 </tr>
 
 <tr>
  <th width="40%">RF power</th>
  <td><input type="text" name="RF_power" size="20" maxlength="12" value="<% fmcatv_checkWrite("RF_power"); %>" readonly="true" disabled></td>
 </tr>
 
 
 <tr>
  <th width="40%">temperature</th>
  <td><input type="text" name="temperature" size="20" maxlength="12" value="<% fmcatv_checkWrite("temperature"); %>" readonly="true" disabled></td>
 </tr>
 <tr>
  <th width="40%">work mode</th>
  <td><input type="text" name="work_mode" size="20" maxlength="12" value="<% fmcatv_checkWrite("work_mode"); %>" readonly="true" disabled></td>
 </tr>
</table>
<table>
 <tr>
  <th width="40%">RF att set</th>
  <td>
      <select id="RF_att_set" name="RF_att_set">
     <option value="0">0.0 dB</option>
     <option value="10">-1.0 dB</option>
     <option value="20">-2.0 dB</option>
     <option value="30">-3.0 dB</option>
     <!--	
     <option value="20">-4.0 dB</option>
     <option value="25">-5.0 dB</option>
     <option value="30">-6.0 dB</option>
     <option value="35">-7.0 dB</option>
     <option value="40">-8.0 dB</option>
     <option value="45" selected="selected">-9.0 dB</option>
     <option value="50">-10.0 dB</option>
     <option value="55">-11.0 dB</option>
     <option value="60">-12.0 dB</option>
     -->
     <option value="N/A">N/A</option>
   </select>
  </td>
 </tr>
 <tr>
  <th width="40%">RF switch</th>
  <td>
      <select id="RF_switch" name="RF_switch">
      <option value="0">Open</option>
      <option value="1">Close</option>
      <option value="N/A">N/A</option>
   </select>
  </td>
 </tr>
 
 <tr>
  <th width="40%">hd version</th>
  <td><input type="text" name="hd_version" size="20" maxlength="12" value="<% fmcatv_checkWrite("hd_version"); %>" readonly="true" disabled></td>
 </tr>
 <tr>
  <th width="40%">sw version</th>
  <td><input type="text" name="sw_version" size="20" maxlength="12" value="<% fmcatv_checkWrite("sw_version"); %>" readonly="true" disabled></td>
 </tr>
</table>
</div>

<div class="adsl clearfix">
 <input type="hidden" value="/catv.asp" name="submit-url">
 <input class="link_bg" type="submit" value="<% multilang(LANG_APPLY_CHANGES); %>" name="save"  onclick="WebDoSubmit();">
 <input class="link_bg" type="button" value="<% multilang(LANG_REFRESH); %>" name="refresh" onClick="javascript: window.location.reload()">
<input type="hidden" name="postSecurityFlag" value="">
</div>

</form>
<!-- </center> -->
</body>
</html>
