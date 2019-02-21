<html>
<! Copyright (c) Realtek Semiconductor Corp., 2003. All Rights Reserved. ->
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<title><% multilang(LANG_ETHERNETOAM); %></title>
<link rel="stylesheet" type="text/css" href="common_style.css" />
<script type="text/javascript" src="share.js">
</script>
<SCRIPT>
function validateKeyforMAC(str)
{
   for (var i=0; i<str.length; i++) {
    if ( (str.charAt(i) >= '0' && str.charAt(i) <= '9') ||
    		(str.charAt(i) == ':' ) || 
    		(str.charAt(i) >= 'A' && str.charAt(i) <= 'F')||
    		(str.charAt(i) >= 'a' && str.charAt(i) <= 'f') )
			continue;
	return 0;
  }
  return 1;
}

function getDigitValueforMac(str, num)
{
  i=1;
  if ( num != 1 ) {
  	while (i!=num && str.length!=0) {
		if ( str.charAt(0) == ':' ) {
			i++;
		}
		str = str.substring(1);
  	}
  	if ( i!=num )
  		return -1;
  }
  for (i=0; i<str.length; i++) {
  	if ( str.charAt(i) == ':' ) {
		str = str.substring(0, i);
		break;
	}
  }
  if ( str.length == 0)
  	return -1;
  d = parseInt(str, 10);
  return d;
}

function checkRangeforMAC(str, num, min, max)
{  
  d = getDigitValueforMac(str,num);
  if ( d > max || d < min )
      	return false;
  return true;
}

function checkClick(type)
{
	var str = document.Y1731.targetMac.value;
	var macdigit = 0;
	var str2 = document.Y1731.ttl.value; 
	
	if( type == 2) {
	if ( str2.length == 0) {
		alert("Input Linktrace TTL. It shoulde be 1~255.");
		document.Y1731.ttl.focus();
		return false;
  	}
	}
	
  	if ( str.length != 17) {
		alert("Input Host MAC address is not complete. It should be 17 digits in hex.");
		document.Y1731.targetMac.focus();
		return false;
  	} 	
	if (document.Y1731.vid.value !="" ) {
		if ((document.Y1731.vid.value<1 || document.Y1731.vid.value>4094)) {  
			alert('VLAN ID must be 1~4094');
			return false;
		}
	}
	
	if (document.Y1731.targetMac.value=="") {
		alert("Enter Target MAC Addres !");
		document.Y1731.targetMac.focus();
		return false;
	}
	
	for (var i=0; i<str.length; i++) {
		if ((str.charAt(i) == 'f') || (str.charAt(i) == 'F'))
			macdigit ++;
		else
			continue;
	}
	if (macdigit == 12 || str == "00:00:00:00:00:00") {
		alert("Invalid MAC address.");
		document.Y1731.targetMac.focus();
		return false;
	}	
	
	if ( validateKeyforMAC( document.Y1731.targetMac.value ) == 0 ) {
		alert("Invalid Target MAC Address. It should be in hex number (0-9 or a-f or A-F)");
		document.Y1731.targetMac.focus();
		return false;
	}	
	
	if ( !checkRangeforMAC(document.Y1731.targetMac.value,1,0,255) ) {
		alert('Invalid Target MAC in 1st hex number of Host MAC Address. It should be 0x00-0xff.');
		document.Y1731.targetMac.focus();
		return false;
	}
	
	if ( !checkRangeforMAC(document.Y1731.targetMac.value,2,0,255) ) {
		alert('Invalid Target NAC in 2nd hex number of Host MAC Address. It should be 0x00-0xff.');
		document.Y1731.targetMac.focus();
		return false;
	}
	
	if ( !checkRangeforMAC(document.Y1731.targetMac.value,3,0,255) ) {
		alert('Invalid Target MAC in 3rd hex number of Host MAC Address. It should be 0x00-0xff.');
		document.Y1731.targetMac.focus();
		return false;
	}
	
	if ( !checkRangeforMAC(document.Y1731.targetMac.value,4,0,254) ) {
		alert('Invalid Target MAC in 4th hex number of Host MAC Address. It should be 0x00-0xff.');
		document.Y1731.targetMac.focus();
		return false;
	}
	
	if ( !checkRangeforMAC(document.Y1731.targetMac.value,5,0,255) ) {
		alert('Invalid Traget MAC in 5rd hex number of Host MAC Address. It should be 0x00-0xff.');
		document.Y1731.targetMac.focus();
		return false;
	}
	
	if ( !checkRangeforMAC(document.Y1731.targetMac.value,6,0,255) ) {
		alert('Invalid Target AMC in 6th hex number of Host MAC Address. It should be 0x00-0xff.');
		document.Y1731.targetMac.focus();
		return false;
	}
		
	return true;
}

function saveChanges(){
	if (document.Y1731.oamMode.value == 1) {
		if (document.Y1731.myid.value =="" ) {
			alert('Myid must have value');
			return false;
		}
		
		if ((document.Y1731.myid.value<1 || document.Y1731.myid.value>8191)) {  
			alert('Myid must be 1~8191');
			return false;
		}
		
		if (document.Y1731.vid.value !="" ) {
			if ((document.Y1731.vid.value<1 || document.Y1731.vid.value>4094)) {  
				alert('VLAN ID must be 1~4094');
				return false;
			}
		}
		if (document.Y1731.megid.value == "") {  
			alert('MEGID must have value');
			return false;
		}
	}
	return true;
}

function updateInput()
{
	if (document.Y1731.ccmenable.checked == true) {
		if (document.getElementById)  // DOM3 = IE5, NS6
			document.getElementById('CCMShow').style.display = 'block';
			else {
			if (document.layers == false) // IE4
				document.all.CCMShow.style.display = 'block';
		}
	} else {
		if (document.getElementById)  // DOM3 = IE5, NS6
			document.getElementById('CCMShow').style.display = 'none';
		else {
			if (document.layers == false) // IE4
				document.all.CCMShow.style.display = 'none';
		}
	}
}

function enableText()
{
	enableTextField(document.Y1731.oamMode);
	enableTextField(document.Y1731.meglevel);
	enableTextField(document.Y1731.myid);
	enableTextField(document.Y1731.vid);
	enableTextField(document.Y1731.ccmenable);
	enableTextField(document.Y1731.ccminterval);
	enableTextField(document.Y1731.megid);	
	enableTextField(document.Y1731.loglevel);
}

function disableText()
{
	disableTextField(document.Y1731.oamMode);
	disableTextField(document.Y1731.meglevel);
	disableTextField(document.Y1731.myid);
	disableTextField(document.Y1731.vid);
	disableTextField(document.Y1731.ccmenable);
	disableTextField(document.Y1731.ccminterval);
	disableTextField(document.Y1731.megid);	
	disableTextField(document.Y1731.loglevel);
}

function updateState()
{  
  disableText();
  
  if (document.Y1731.oamMode[1].checked) {
	enableText();
	document.getElementById("printMEGID").innerHTML = "<b>MEG ID</b>";	
	document.getElementById("printMEGL").innerHTML = "<b>MEG Level</b>";
	return true;
  }
  if (document.Y1731.oamMode[2].checked) { 
	enableText();
	document.getElementById("printMEGID").innerHTML = "<b>MA ID</b>";
	document.getElementById("printMEGL").innerHTML = "<b>MA Level</b>";
	return true;
  }
 
  return true;
}

</SCRIPT>
</head>

<body>
<blockquote>
<h2 class="page_title"><% multilang(LANG_ETHERNETOAM); %></font></h2>

<form action=/boaform/formY1731 method=POST name="Y1731">
<table>
  <tr><td><font size=2>
    <% multilang(LANG_HERE_YOU_CAN_CONFIGURE_ETHERNETOAM); %>
  </font></td></tr>
  <!--<tr><td><hr size=1 noshade align=top></td></tr>-->
</table>

<div ID="Show8023ah" style="display:none">
<table>
 <tr><td><hr size=1 noshade align=top></td></tr>
</table>
<table>
 <tr>
  <th>802.3ah <% multilang(LANG_ENABLE); %>:</th>
  <td><input type="checkbox" name="oam8023ahMode" id="oam8023ahMode" value="1" checked></td>
 </tr>
 
 <tr>
  <th><% multilang(LANG_WAN_INTERFACE); %>:</th>
  <td>
      <select name="efm_8023ah_ext_if">	
	<% if_wan_list("efm_8023ah"); %>
      </select>
  </td>
 </tr>
 
 <tr>
	<th><% multilang(LANG_CAPABILITY); %>:</th>
	<td></td>
 </tr>
 <tr>
	<th></th>
	<td><input type="checkbox" name="8023ahActive" id="8023ahActive" value="1">Active</td>
 </tr> 

</table>
</div>

<div ID="ShowY1731p1" style="display:none">
<table>
 <tr><td><hr size=1 noshade align=top></td></tr>
</table>

<table> 
 <tr>
  <th>CFM:</th>
  <td><input type="radio" name="oamMode" value="0" onClick="updateState()"><% multilang(LANG_DISABLE); %>&nbsp;&nbsp;
                <input type="radio" name="oamMode" value="1" onClick="updateState()">Y.1731 <% multilang(LANG_ENABLE); %>&nbsp;&nbsp;
                <input type="radio" name="oamMode" value="2" onClick="updateState()">802.1ag <% multilang(LANG_ENABLE); %>&nbsp;&nbsp;
  </td>
 </tr>
 
 <tr>
  <th id="printMEGL">MEG Level:</th>
  <td>
   <select size="1" name="meglevel" id="meglevel">
   <option value="7">7</option><option value="6">6</option><option value="5">5</option><option value="4">4</option>
   <option value="3">3</option><option value="2">2</option><option value="1">1</option><option value="0">0</option>
   </select>
  </td>
 </tr>
 <tr>
  <th>Local MEP ID:</b></th>
  <td><input type="text" name="myid" id="myid" size="5" maxlength="5">[1-8191]</td>
 </tr>
 <tr>
  <th id="printMEGID">MEG ID:</th>
  <td><input type="text" name="megid" id="megid" size="14" maxlength="14">[e.g. Realtek]</td>
 </tr>
 <tr>
  <th>802.1Q VLAN ID:</th>
  <td><input type="text" name="vid" id="vid" size="6" maxlength="14">(1-4094),empty means no VLAN tag</td>
 </tr>
 
 <tr>
  <th>CCM Transmission</th>
  <td><input type="checkbox" name="ccmenable" id="ccmenable" value="1" onClick=updateInput()></td>
 </tr>
</table>
</div>

<div ID="CCMShow" style="display:none">
<table>
  <tr>
  <th>CCM Interval:</th>
  <td>
   <select size="1" name="ccminterval" id="ccminterval">
   <option value="1">3.33ms</option><option value="2">10ms</option><option value="3">100ms</option>
   <option value="4">1s</option><option value="5">10s</option><option value="6">1min</option><option value="7">10min</option>
   </select>
  </td>
 </tr>   
</table></div>

<div ID="ShowY1731p2" style="display:none">
<table>
 <tr>
  <th>Log Level:</th>
  <td>
   <select size="1" name="loglevel" id="loglevel">
   <option value="none">none</option><option value="medium">medium</option><option value="xtra">extra</option><option value="all">all</option>
   </select>
  </td>
 </tr>   
</table>

<table>
	<tr><td><hr size=1 noshade align=top></td></tr>
	<tr>
  	<td style="font-size: 18; font-weight: bold">
			<% multilang(LANG_LOOPBACK_AND_LINKTRACETEST); %>:
  	</td>
  </tr>
</table>

<table>
 <tr>
  <th><% multilang(LANG_WAN_INTERFACE); %>:</th>
  <td>
      <select name="ext_if">	
	<% if_wan_list("efm_8023ah"); %>	
      </select>
  </td>
 </tr>
 
 <tr>
  <th>Target MAC:</th>
  <td><input type="text" name="targetMac" id="targetMac" size="10" maxlength="18">[e.g. 02:20:30:aa:bb:cc]</td>
 </tr>
 
 <tr>
  <th>Linktrace TTL:</th>
  <td><input type="text" name="ttl" id="ttl" size="10" maxlength="10" value="-1">[1-255](-1 means no max hop limit)</td>
 </tr>
 
 <tr bgcolor="#EEEEEE">
    <th><% multilang(LANG_LINKTRACE_RESULT); %></th>
    <td><% getLinktraceMac(); %></td>
 </tr>  
</table>
</div>

 <input type=submit value="<% multilang(LANG_SEND_LOOPBACK); %>" name="loopback" onClick="return checkClick(1)">&nbsp;&nbsp;
 <input type=submit value="<% multilang(LANG_SEND_LINKTRACE); %>" name="linktrace" onClick="return checkClick(2)">&nbsp;&nbsp;&nbsp;
 <input type=hidden value="/ethoam.asp" name="submit-url">  
 <br>
 <input type=submit value="<% multilang(LANG_APPLY_CHANGES); %>" name="save" onClick="return saveChanges()">
 <input type=hidden value="/ethoam.asp" name="submit-url">
<script>
	<% initPage("ethoamY1731"); %>	
	updateState();
</script>
<script>	
	updateInput();
	<% initPage("ethoam8023ah"); %>
</script>  
</form>
</blockquote>
</body>

</html>
