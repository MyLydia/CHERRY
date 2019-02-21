<% SendWebHeadStr();%>
<meta HTTP-EQUIV='Pragma' CONTENT='no-cache'>
<meta HTTP-equiv="Cache-Control" content="no-cache">
<title>Active Wireless Client Table</title>

<style>
.on {display:on}
.off {display:none}	
</style>
<script language="JavaScript" type="text/javascript">
var vap_num;
var vap_id;

function init()
{
	var url_tmp = location.href;
	var url_tmp_1 = url_tmp.split("?");
	var found = url_tmp_1[1].indexOf("%3D");
	if (found == -1) {
		var id = url_tmp_1[1].split("=");
		vap_id = id[1]*1;
	}
	else
		vap_id = parseInt(url_tmp_1[1].substring(5, 6));

	get_by_id("submit-url").value = "/admin/wlstatbl_vap.asp?id="+vap_id;
}

function on_submit()
{
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	return true;
}
</script>
</head>

<body>
<form action=/boaform/admin/formWirelessVAPTbl method=POST name="formWirelessVAPTbl">
<input type="hidden" value="" id="submit-url" name="submit-url">
<div class="intro_main ">
<p class="intro_title">Active Wireless Client Table
<script>
	init();
	if (vap_id == 1) {
		document.write(" - AP1");
		vap_num = 1;
	}
	else if (vap_id == 2) {
		document.write(" - AP2");
		vap_num = 2;
	}
	else if (vap_id == 3) {
		document.write(" - AP3");
		vap_num = 3;
	}
	else if (vap_id == 4) {
		document.write(" - AP4");
		vap_num = 4;
	}
	else {
		alert("<% multilang(LANG_WE_CAN_NOT_PROCESS_AP_THE_WINDOWS_WILL_BE_CLOSED); %>");
		window.opener=null;   
		window.open("","_self");   
		window.close();
	}
</script>
</p>

<p class="intro_content">
	This table shows the MAC address, transmission, receiption packet counters and encrypted
	status for each associated wireless client.
</p>
</div>
<div class="data_common data_vertical">
<script> if (vap_num != 1) document.write("</table><span class = \"off\" ><table>"); </script>
<table>
<tr>
	<th width="100">MAC Address</th>
	<th width="60">Mode</th>
	<th width="60">Tx Packet</th>
	<th width="60">Rx Packet</th>
	<th width="60">Tx Rate (Mbps)</th>
	<th width="60">Power Saving</th>
	<th width="60">Expired Time (s)</th>
</tr>
<% wirelessVAPClientList(" ", "1"); %>
<script> if (vap_num != 1) document.write("</table></span><table >"); </script>

<script> if (vap_num != 2) document.write("</table><span class = \"off\" ><table>"); </script>
<tr>
	<th width="100">MAC Address</th>
	<th width="60">Mode</th>
	<th width="60">Tx Packet</th>
	<th width="60">Rx Packet</th>
	<th width="60">Tx Rate (Mbps)</th>
	<th width="60">Power Saving</th>
	<th width="60">Expired Time (s)</th>
</tr>
<% wirelessVAPClientList(" ", "2"); %>
<script> if (vap_num != 2) document.write("</table></span><table >"); </script>

<script> if (vap_num != 3) document.write("</table><span class = \"off\" ><table>"); </script>
<tr>
	<th width="100">MAC Address</th>
	<th width="60">Mode</th>
	<th width="60">Tx Packet</th>
	<th width="60">Rx Packet</th>
	<th width="60">Tx Rate (Mbps)</th>
	<th width="60">Power Saving</th>
	<th width="60">Expired Time (s)</th>
</tr>
<% wirelessVAPClientList(" ", "3"); %>
<script> if (vap_num != 3) document.write("</table></span><table>"); </script>

<script> if (vap_num != 4) document.write("</table><span class = \"off\" ><table>"); </script>
<tr>
	<th width="100">MAC Address</th>
	<th width="60">Mode</th>
	<th width="60">Tx Packet</th>
	<th width="60">Rx Packet</th>
	<th width="60">Tx Rate (Mbps)</th>
	<th width="60">Power Saving</th>
	<th width="60">Expired Time (s)</th>
</tr>
<% wirelessVAPClientList(" ", "4"); %>
<script> if (vap_num != 4) document.write("</table></span><table>"); </script>

</table>
</div>
<div class="btn_ctl">
  <input type="submit" value="Refresh" onClick="return on_submit()" class="link_bg">&nbsp;&nbsp;
  <input type="button" value=" Close " name="close" onClick="javascript: window.close();" class="link_bg">
  <input type="hidden" name="postSecurityFlag" value="">
 </div> 
</form>
<br><br>
</body>

</html>
