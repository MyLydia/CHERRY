<%SendWebHeadStr(); %>
<title>DoS<% multilang(LANG_CONFIGURATION); %></title>

<script>
var dosEnabled=0 ;
var rg_config=<% checkWrite("config_rtk_rg"); %>;
function  setDosEnabled() {

}

function dosEnabledClick(){
	if(document.DosCfg.dosEnabled.checked){
		enableTextField(document.DosCfg.sysfloodSYN);
		enableTextField(document.DosCfg.sysfloodFIN);
		enableTextField(document.DosCfg.sysfloodUDP);
		enableTextField(document.DosCfg.sysfloodICMP);
		enableTextField(document.DosCfg.sysfloodSYNcount);
		enableTextField(document.DosCfg.sysfloodFINcount);
		enableTextField(document.DosCfg.sysfloodUDPcount);
		enableTextField(document.DosCfg.sysfloodICMPcount);
		enableTextField(document.DosCfg.ipfloodSYN);
		enableTextField(document.DosCfg.ipfloodFIN);
		enableTextField(document.DosCfg.ipfloodUDP);
		enableTextField(document.DosCfg.ipfloodICMP);
		enableTextField(document.DosCfg.ipfloodSYNcount);
		enableTextField(document.DosCfg.ipfloodFINcount);
		enableTextField(document.DosCfg.ipfloodUDPcount);
		enableTextField(document.DosCfg.ipfloodICMPcount);
		enableTextField(document.DosCfg.TCPUDPPortScan);
		enableTextField(document.DosCfg.portscanSensi);
		enableTextField(document.DosCfg.ICMPSmurfEnabled);
		enableTextField(document.DosCfg.IPLandEnabled);
		enableTextField(document.DosCfg.IPSpoofEnabled);
		enableTextField(document.DosCfg.IPTearDropEnabled);
		enableTextField(document.DosCfg.PingOfDeathEnabled);
		enableTextField(document.DosCfg.TCPScanEnabled);
		enableTextField(document.DosCfg.TCPSynWithDataEnabled);
		enableTextField(document.DosCfg.UDPBombEnabled);
		enableTextField(document.DosCfg.UDPEchoChargenEnabled);
		enableTextField(document.DosCfg.sourceIPblock);
		enableTextField(document.DosCfg.IPblockTime);
	}
	else{
		document.DosCfg.sysfloodSYN.checked=0;
		document.DosCfg.sysfloodFIN.checked=0;
		document.DosCfg.sysfloodUDP.checked=0;
		document.DosCfg.sysfloodICMP.checked=0;
		document.DosCfg.ipfloodSYN.checked=0;
		document.DosCfg.ipfloodFIN.checked=0;
		document.DosCfg.ipfloodUDP.checked=0;
		document.DosCfg.ipfloodICMP.checked=0;
		document.DosCfg.TCPUDPPortScan.checked=0;
		document.DosCfg.ICMPSmurfEnabled.checked=0;
		document.DosCfg.IPLandEnabled.checked=0;
		document.DosCfg.IPSpoofEnabled.checked=0;
		document.DosCfg.IPTearDropEnabled.checked=0;
		document.DosCfg.PingOfDeathEnabled.checked=0;
		document.DosCfg.TCPScanEnabled.checked=0;
		document.DosCfg.TCPSynWithDataEnabled.checked=0;
		document.DosCfg.UDPBombEnabled.checked=0;
		document.DosCfg.UDPEchoChargenEnabled.checked=0;
		document.DosCfg.sourceIPblock.checked=0;
		disableTextField(document.DosCfg.sysfloodSYN);
		disableTextField(document.DosCfg.sysfloodFIN);
		disableTextField(document.DosCfg.sysfloodUDP);
		disableTextField(document.DosCfg.sysfloodICMP);
		disableTextField(document.DosCfg.sysfloodSYNcount);
		disableTextField(document.DosCfg.sysfloodFINcount);
		disableTextField(document.DosCfg.sysfloodUDPcount);
		disableTextField(document.DosCfg.sysfloodICMPcount);
		disableTextField(document.DosCfg.ipfloodSYN);
		disableTextField(document.DosCfg.ipfloodFIN);
		disableTextField(document.DosCfg.ipfloodUDP);
		disableTextField(document.DosCfg.ipfloodICMP);
		disableTextField(document.DosCfg.ipfloodSYNcount);
		disableTextField(document.DosCfg.ipfloodFINcount);
		disableTextField(document.DosCfg.ipfloodUDPcount);
		disableTextField(document.DosCfg.ipfloodICMPcount);
		disableTextField(document.DosCfg.TCPUDPPortScan);
		disableTextField(document.DosCfg.portscanSensi);
		disableTextField(document.DosCfg.ICMPSmurfEnabled);
		disableTextField(document.DosCfg.IPLandEnabled);
		disableTextField(document.DosCfg.IPSpoofEnabled);
		disableTextField(document.DosCfg.IPTearDropEnabled);
		disableTextField(document.DosCfg.PingOfDeathEnabled);
		disableTextField(document.DosCfg.TCPScanEnabled);
		disableTextField(document.DosCfg.TCPSynWithDataEnabled);
		disableTextField(document.DosCfg.UDPBombEnabled);
		disableTextField(document.DosCfg.UDPEchoChargenEnabled);
		disableTextField(document.DosCfg.sourceIPblock);
		disableTextField(document.DosCfg.IPblockTime);
	}
}

function SelectAll(){
	if(document.DosCfg.dosEnabled.checked){
		document.DosCfg.sysfloodSYN.checked=1;
		document.DosCfg.sysfloodFIN.checked=1;
		document.DosCfg.sysfloodUDP.checked=1;
		document.DosCfg.sysfloodICMP.checked=1;
		document.DosCfg.ipfloodSYN.checked=1;
		document.DosCfg.ipfloodFIN.checked=1;
		document.DosCfg.ipfloodUDP.checked=1;
		document.DosCfg.ipfloodICMP.checked=1;
		document.DosCfg.TCPUDPPortScan.checked=1;
		document.DosCfg.ICMPSmurfEnabled.checked=1;
		document.DosCfg.IPLandEnabled.checked=1;
		document.DosCfg.IPSpoofEnabled.checked=1;
		document.DosCfg.IPTearDropEnabled.checked=1;
		document.DosCfg.PingOfDeathEnabled.checked=1;
		document.DosCfg.TCPScanEnabled.checked=1;
		document.DosCfg.TCPSynWithDataEnabled.checked=1;
		document.DosCfg.UDPBombEnabled.checked=1;
		document.DosCfg.UDPEchoChargenEnabled.checked=1;
	}
}

function ClearAll(){
	if(document.DosCfg.dosEnabled.checked){
		document.DosCfg.sysfloodSYN.checked=0;
		document.DosCfg.sysfloodFIN.checked=0;
		document.DosCfg.sysfloodUDP.checked=0;
		document.DosCfg.sysfloodICMP.checked=0;
		document.DosCfg.ipfloodSYN.checked=0;
		document.DosCfg.ipfloodFIN.checked=0;
		document.DosCfg.ipfloodUDP.checked=0;
		document.DosCfg.ipfloodICMP.checked=0;
		document.DosCfg.TCPUDPPortScan.checked=0;
		document.DosCfg.ICMPSmurfEnabled.checked=0;
		document.DosCfg.IPLandEnabled.checked=0;
		document.DosCfg.IPSpoofEnabled.checked=0;
		document.DosCfg.IPTearDropEnabled.checked=0;
		document.DosCfg.PingOfDeathEnabled.checked=0;
		document.DosCfg.TCPScanEnabled.checked=0;
		document.DosCfg.TCPSynWithDataEnabled.checked=0;
		document.DosCfg.UDPBombEnabled.checked=0;
		document.DosCfg.UDPEchoChargenEnabled.checked=0;
	}
}

function saveChanges(){
	if(rg_config=="yes"){
		if(document.DosCfg.sysfloodSYN.checked){
			if(document.DosCfg.sysfloodSYNcount.value < 5){				
				alert('<% multilang(LANG_MUST_LARGER_THAN_5_PACKETS_SECOND); %>');
				return false;
			}
		}
		if(document.DosCfg.sysfloodFIN.checked){
			if(document.DosCfg.sysfloodFINcount.value < 5){				
				alert('<% multilang(LANG_MUST_LARGER_THAN_5_PACKETS_SECOND); %>');
				return false;
			}
		}
		if(document.DosCfg.sysfloodICMP.checked){
			if(document.DosCfg.sysfloodICMPcount.value < 5){				
				alert('<% multilang(LANG_MUST_LARGER_THAN_5_PACKETS_SECOND); %>');
				return false;
			}
		}
	}
	
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	
	return true;
}

</script>
</head>



<body>
<div class="intro_main ">
	<p class="intro_title">DoS <% multilang(LANG_CONFIGURATION); %></p>
	<p class="intro_content">  <% multilang(LANG_DOS_DENIAL_OF_SERVICE_ATTACK_WHICH_IS_LAUNCHED_BY_HACKER_AIMS_TO_PREVENT_LEGAL_USER_FROM_TAKING_NORMAL_SERVICES_IN_THIS_PAGE_YOU_CAN_CONFIGURE_TO_PREVENT_SOME_KINDS_OF_DOS_ATTACK); %></p>
	<checkWrite("ModifyTip");>
</div>

<form action=/boaform/admin/formDosCfg method=POST name="DosCfg">
<div class="data_common data_common_notitle">
	<table>
		<tr>
			<th width="30%">
				<input type="checkbox" name="dosEnabled" value="ON" onclick="dosEnabledClick()"> <% multilang(LANG_ENABLE_DOS_BLOCK); %>
			</th>
		</tr>
	</table>
</div>
<div class="data_common data_common_notitle">
	<table>
		<tr>
			<th width="50%"><input type="checkbox" name="sysfloodSYN" value="ON" >  Whole System Flood: SYN </th>
			<td width="50%"><input type="text" name="sysfloodSYNcount" size="6" maxlength="4" value=<% getInfo("syssynFlood"); %> >  packets/second</td>
		</tr>
		<tr>
			<th><input type="checkbox" name="sysfloodFIN"  value="ON" >  Whole System Flood: FIN </th>
			<td><input type="text" name="sysfloodFINcount" size="6" maxlength="4" value=<% getInfo("sysfinFlood"); %> >  packets/second</td>
		</tr>
		<tr>
			<th><input type="checkbox" name="sysfloodUDP"  value="ON" >  Whole System Flood: UDP </th>
			<td><input type="text" name="sysfloodUDPcount" size="6" maxlength="4" value=<% getInfo("sysudpFlood"); %> >  packets/second</td>
		<tr>
			<th><input type="checkbox" name="sysfloodICMP"  value="ON" >  Whole System Flood: ICMP </th>
			<td><input type="text" name="sysfloodICMPcount" size="6" maxlength="4" value=<% getInfo("sysicmpFlood"); %> >  packets/second<br></td>
		</tr>
		<tr>
			<th><input type="checkbox" name="ipfloodSYN"  value="ON" >  Per-Source IP Flood: SYN </th>
			<td><input type="text" name="ipfloodSYNcount" size="6" maxlength="4" value=<% getInfo("pipsynFlood"); %> >  packets/second</td>
		</tr>
		<tr>
			<th><input type="checkbox" name="ipfloodFIN"  value="ON" >  Per-Source IP Flood: FIN </th>
			<td><input type="text" name="ipfloodFINcount" size="6" maxlength="4" value=<% getInfo("pipfinFlood"); %> >  packets/second</td>
		</tr>
		<tr>
			<th><input type="checkbox" name="ipfloodUDP"  value="ON" >  Per-Source IP Flood: UDP </th>
			<td><input type="text" name="ipfloodUDPcount" size="6" maxlength="4" value=<% getInfo("pipudpFlood"); %> >  packets/second</td>
		</tr>
		<tr>
			<th><input type="checkbox" name="ipfloodICMP"  value="ON" >  Per-Source IP Flood: ICMP </th>
			<td><input type="text" name="ipfloodICMPcount" size="6" maxlength="4" value=<% getInfo("pipicmpFlood"); %> >  packets/second</td>
		</tr>
		<tr>
			<th><input type="checkbox" name="TCPUDPPortScan"  value="ON" >  TCP/UDP PortScan </th>
			<td>
				<select name="portscanSensi">
				<option value=0 > Low </option>
				<option value=1 > High </option>
				</select>
				Sensitivity 
			</td>
		</tr>
		<tr>
			<th colspan="2"><input type="checkbox" name="ICMPSmurfEnabled"  value="ON" >  ICMP Smurf </th>
		</tr>
		<tr>
			<th colspan="2"><input type="checkbox" name="IPLandEnabled" value="ON" >  IP Land </th>
		</tr>
		<tr>
			<th colspan="2"><input type="checkbox" name="IPSpoofEnabled" value="ON" >  IP Spoof </th>
		</tr>
		<tr>
			<th colspan="2"><input type="checkbox" name="IPTearDropEnabled" value="ON" >  IP TearDrop </th>
		</tr>
		<tr>
			<th colspan="2"><input type="checkbox" name="PingOfDeathEnabled"  value="ON" >  PingOfDeath </th>
		</tr>
		<tr>
			<th colspan="2"><input type="checkbox" name="TCPScanEnabled"  value="ON" >  TCP Scan </th>
		</tr>
		<tr>
			<th colspan="2"><input type="checkbox" name="TCPSynWithDataEnabled"   value="ON" >  TCP SynWithData </th>
		</tr>
		<tr>
			<th colspan="2"><input type="checkbox" name="UDPBombEnabled"  value="ON" >  UDP Bomb </th>
		</tr>
		<tr>
			<th colspan="2"><input type="checkbox" name="UDPEchoChargenEnabled"   value="ON" >  UDP EchoChargen </th>
		</tr>
	</table>
</div>
<div class="btn_ctl clearfix">
    <input class="link_bg" type="button" value="<% multilang(LANG_SELECT_ALL); %>" name="selectAll" onClick="SelectAll()">&nbsp;&nbsp;
    <input class="link_bg" type="button" value="<% multilang(LANG_CLEAR); %>" name="clearAll" onClick="ClearAll()">&nbsp;&nbsp;
</div>
<div class="data_common data_common_notitle">
	<table>
		<tr>
			<th width="50%"><input type="checkbox" name="sourceIPblock"  value="ON" >  <% multilang(LANG_ENABLE_SOURCE_IP_BLOCKING); %> </th>
			<td width="50%"><input type="text" name="IPblockTime" size="4" maxlength="3" value=<% getInfo("blockTime"); %> >  <% multilang(LANG_BLOCK_INTERVAL); %> (<% multilang(LANG_SECONDS); %>)</td>
		</tr>
	</table>
</div>
<div class="btn_ctl clearfix">
	<input class="link_bg" type="submit" value="<% multilang(LANG_APPLY_CHANGES); %>" onClick="return saveChanges()">&nbsp;&nbsp;
	<input type="hidden" value="/dos.asp" name="submit-url">
	<input type="hidden" name="postSecurityFlag" value="">
</div>  
<script>
	<% initPage("dos"); %>
</script>
<script>
	dosEnabledClick();
</script>
</form>
</table>
<br><br>
</body>
</html>
