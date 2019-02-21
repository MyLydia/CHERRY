<%SendWebHeadStr(); %>
<title>IPsec VPN Configuration</title>

<SCRIPT>
<% ipsecAlgoScripts(); %>
/*
function dh_p2_change(str, idx){
	if(document.getElementById(str).checked == true)
		dh_algo_p2 |= (1<<parseInt(idx));
	else
		dh_algo_p2 &= ~(1<<parseInt(idx));
		
}
*/
function encrypt_p2_change(str, idx){
	if(document.getElementById(str).checked == true)
		encrypt_algo_p2 |= (1<<parseInt(idx));
	else
		encrypt_algo_p2 &= ~(1<<parseInt(idx));
}

function auth_p2_change(str, idx){
	if(document.getElementById(str).checked == true)
		auth_algo_p2 |= (1<<parseInt(idx));
	else
		auth_algo_p2 &= ~(1<<parseInt(idx));
}

function checkit(obj){
	if(obj.value=="")
		obj.value=obj.defaultValue;
}

function clearit(obj){
	if(obj.value==obj.defaultValue)
		obj.value="";
}

function checkKey(obj, len)
{
	if(obj.value==""){		
		alert('<% multilang(LANG_PLEASE_ENTER_KEY); %>');
		obj.focus();
		return false;
	}
	for (var i=0; i<obj.value.length; i++) {
		if ((obj.value.charAt(i) >= '0' && obj.value.charAt(i) <= '9')||(obj.value.charAt(i) >= 'a' && obj.value.charAt(i) <= 'f')||(obj.value.charAt(i) >= 'A' && obj.value.charAt(i) <= 'F'))
			continue;		
		alert('<% multilang(LANG_PLEASE_ENTER_HEXADECIMAL_NUMBER); %>');
		obj.focus();
		return false;
	}
	if(obj.value.length != len){
		alert("Error, key length should be "+len+" !");		
		obj.focus();
		return false;
	}
}

function ipsecSelection()
{
	onClicknegoType();
	onTransModeChange();
	onClickAdvOption();
	onProtocolChange();
	onEncapsTypeChange();
	
	document.ipsec.ikeProposal0.options[1].selected = true;
	document.ipsec.ikeProposal1.options[2].selected = true;
	document.ipsec.ikeProposal2.options[3].selected = true;
	document.ipsec.ikeProposal3.options[4].selected = true;

}

function onClicknegoType()
{
	if(document.ipsec.negoType[1].checked){
		document.getElementById('manualHead').style.display='';
		document.getElementById('manualAlgorithms').style.display='';
		document.getElementById('autoHead').style.display='none';
		document.getElementById('pskTable').style.display='none';
		if(document.ipsec.advOption.checked)
			document.getElementById('autoAdv').style.display='none';
	}
	else{
		document.getElementById('manualHead').style.display='none';
		document.getElementById('manualAlgorithms').style.display='none';
		document.getElementById('autoHead').style.display='';
		document.getElementById('pskTable').style.display='';
		if(document.ipsec.advOption.checked)
			document.getElementById('autoAdv').style.display='';
	}
}

function onIKEAuthMethodChange()
{
	if(document.ipsec.ikeAuthMethod.value =="0"){
		//Pre Share Key
		document.getElementById('psk_clumn').style.display='';
	}else{
		document.getElementById('psk_clumn').style.display='none';
	}
}

function onClickAdvOption()
{
	if(document.ipsec.advOption.checked){
		document.getElementById('adv').style.display='';
		if(document.ipsec.negoType[0].checked)
			document.getElementById('autoAdv').style.display='block';
	}
	else{
		document.getElementById('adv').style.display='none';
		document.getElementById('autoAdv').style.display='none';
	}
}

function onProtocolChange()
{
	if(document.ipsec.filterProtocol.value=="0"||document.ipsec.filterProtocol.value=="3"){
		document.ipsec.filterPort.disabled = true;
	}
	else{
		document.ipsec.filterPort.disabled = false;
	}
	
}

function onTransModeChange()
{
	if(document.ipsec.transMode.value =="0"){
		document.getElementById('remoteIntIP').style.display='';
		document.getElementById('remoteMask').style.display='';
		document.getElementById('localIntIP').style.display='';
		document.getElementById('localMask').style.display='';
	}else{
		document.getElementById('remoteIntIP').style.display='none';
		document.getElementById('remoteMask').style.display='none';
		document.getElementById('localIntIP').style.display='none';
		document.getElementById('localMask').style.display='none';
	}
}

function onESPAuthChange(){
	if(document.ipsec.esp_a_algo.value=="0"){
		if(document.ipsec.esp_e_algo.value!="0"){
			document.ipsec.esp_akey.value = "";
			document.ipsec.esp_akey.disabled = true;
		}else{			
			alert('<% multilang(LANG_NEITHER_ENCRYPT_NOR_AUTH_IS_SELECTED); %>');
			document.ipsec.esp_a_algo.focus();
			document.ipsec.esp_a_algo.options[1].selected = true;
		}
	}
	else{
		document.ipsec.esp_akey.disabled = false;
	}
}

function onESPEncryptChange(){
	var objEncrypt = document.getElementByName("esp_e_algo");
	var objAuth = document.getElementByName("esp_a_algo");
	if(document.ipsec.esp_e_algo.value=="0"){
		if(document.ipsec.esp_a_algo.value!="0"){
			document.ipsec.esp_ekey.value = "";
			document.ipsec.esp_ekey.disabled = true;
		}else{			
			alert('<% multilang(LANG_NEITHER_ENCRYPT_NOR_AUTH_IS_SELECTED); %>');
			document.ipsec.esp_e_algo.focus();
			document.ipsec.esp_e_algo.options[1].selected = true;
		}
	}
	else{
		document.ipsec.esp_ekey.disabled = false;
	}
}

function onEncapsTypeChange()
{
	if(document.ipsec.encapsType.value=="1" ||document.ipsec.encapsType.value=="3"){
		document.getElementById('espEncr').style.display='';
		document.getElementById('espEncrKey').style.display='';
		document.getElementById('espAuth').style.display='';
		document.getElementById('espAuthKey').style.display='';
		document.getElementById('espSPI1').style.display='';
		document.getElementById('espSPI2').style.display='';
		document.getElementById('encryptalgo_p2').style.display='';
	}else{
		document.getElementById('espEncr').style.display='none';
		document.getElementById('espEncrKey').style.display='none';
		document.getElementById('espAuth').style.display='none';
		document.getElementById('espAuthKey').style.display='none';
		document.getElementById('espSPI1').style.display='none';
		document.getElementById('espSPI2').style.display='none';
		document.getElementById('encryptalgo_p2').style.display='none';
	}

	if(document.ipsec.encapsType.value=="2" ||document.ipsec.encapsType.value=="3"){
		document.getElementById('ahAuth').style.display='';
		document.getElementById('ahAuthKey').style.display='';
		document.getElementById('ahSPI1').style.display='';
		document.getElementById('ahSPI2').style.display='';
	}else{
		document.getElementById('ahAuth').style.display='none';
		document.getElementById('ahAuthKey').style.display='none';
		document.getElementById('ahSPI1').style.display='none';
		document.getElementById('ahSPI2').style.display='none';
	}
}

function onClickSaveConfig(obj)
{
	var keyLen;
	var objEncrypt;
	var objAuth;
	
	if(checkIP(document.ipsec.rtunnelAddr)==false)
		return false;
		
	if(checkIP(document.ipsec.ltunnelAddr)==false)
		return false;
	if(document.ipsec.transMode.value =="0")
	{
	if(!checkHostIP(document.ipsec.remoteip, 1))
		return false;
		
	if(!checkNetmask(document.ipsec.remotemask, 1))
		return false;	
		
	if(!checkHostIP(document.ipsec.localip, 1))
		return false;
		
		if(!checkNetmask(document.ipsec.localmask, 1))
		return false;
	}
	// manual
	if(document.ipsec.negoType[1].checked){
		if(document.ipsec.encapsType.value=="1" || document.ipsec.encapsType.value=="3"){
			objEncrypt = document.getElementByName("esp_e_algo");
			objAuth = document.getElementByName("esp_a_algo");
			if(document.ipsec.esp_e_algo.value != 0){
				if(document.ipsec.esp_e_algo.value == 1)
					keyLen = 16;
				else if(document.ipsec.esp_e_algo.value == 2)
					keyLen = 48;
				if(checkKey(document.ipsec.esp_ekey, keyLen)==false)
					return false;
			}
			if(document.ipsec.esp_a_algo.value != 0){
				if(document.ipsec.esp_a_algo.value == 1)
					keyLen = 32;
				else if(document.ipsec.esp_a_algo.value == 2)
					keyLen = 40;
				if(checkKey(document.ipsec.esp_akey, keyLen)==false)
					return false;
			}
			
			if(checkDigit(document.ipsec.spi_out_esp.value)==false){				
				alert('<% multilang(LANG_SPI_SHOULD_BE_A_DIGIT_NUMBER); %>');
				document.ipsec.spi_out_esp.focus();
				return false;
			}
			if(checkDigit(document.ipsec.spi_in_esp.value)==false){				
				alert('<% multilang(LANG_SPI_SHOULD_BE_A_DIGIT_NUMBER); %>');
				document.ipsec.spi_in_esp.focus();
				return false;
			}
			if(Number(document.ipsec.spi_out_esp.value)>=0 && Number(document.ipsec.spi_out_esp.value)<=255){				
				alert('<% multilang(LANG_SPI_0_255_IS_RESERVED); %>');
				document.ipsec.spi_out_esp.focus();
				return false;
			}
			if(Number(document.ipsec.spi_in_esp.value)>=0 && Number(document.ipsec.spi_in_esp.value)<=255){				
				alert('<% multilang(LANG_SPI_0_255_IS_RESERVED); %>');
				document.ipsec.spi_in_esp.focus();
				return false;
			}

		}
		else if(document.ipsec.encapsType.value=="2" || document.ipsec.encapsType.value=="3"){
			if(document.ipsec.ah_algo.value == 1)
				keyLen = 32;
			else if(document.ipsec.ah_algo.value == 2)
				keyLen = 40;
			if(checkKey(document.ipsec.ah_key, keyLen)==false)
				return false;
			
			if(checkDigit(document.ipsec.spi_out_ah.value)==false){
				alert('<% multilang(LANG_SPI_SHOULD_BE_A_DIGIT_NUMBER); %>');
				document.ipsec.spi_out_ah.focus();
				return false;
			}
			if(checkDigit(document.ipsec.spi_in_ah.value)==false){
				alert('<% multilang(LANG_SPI_SHOULD_BE_A_DIGIT_NUMBER); %>');
				document.ipsec.spi_in_ah.focus();
				return false;
			}
			if(Number(document.ipsec.spi_out_ah.value)>=0 && Number(document.ipsec.spi_out_ah.value)<=255){
				alert('<% multilang(LANG_SPI_0_255_IS_RESERVED); %>');
				document.ipsec.spi_out_ah.focus();
				return false;
			}
			if(Number(document.ipsec.spi_in_ah.value)>=0 && Number(document.ipsec.spi_in_ah.value)<=255){
				alert('<% multilang(LANG_SPI_0_255_IS_RESERVED); %>');
				document.ipsec.spi_in_ah.focus();
				return false;
			}
		}
	}
	
	if(Number(document.ipsec.filterPort.value)<0 && Number(document.ipsec.filterPort.value)>65535){		
		alert('<% multilang(LANG_PORT_SHOULD_BE_0_65535); %>');
		document.ipsec.filterPort.focus();
		return false;
	}
	if(document.ipsec.negoType[0].checked){
		if(document.ipsec.psk.value.length > 128){			
			alert('<% multilang(LANG_PSK_LENGTH_SHOULD_LESS_THAN_128); %>');
			document.ipsec.filterPort.focus();
			return false;
		}
		if(encrypt_algo_p2==0)
		{
			alert("None Encrypt Algorithm mode for IKE Phase 2 selected");
			return false;
		}
		if(auth_algo_p2==0)
		{
			alert("None Auth Algorithm for IKE Phase 2 selected");
			return false;
		}
		document.ipsec.encrypt_p2.value = encrypt_algo_p2;
		document.ipsec.auth_p2.value = auth_algo_p2;
	}

	obj.isclick = 1;
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	return true;
}

function onClickChangeConfig(obj)
{
	/*
	var obj = document.getElementById("infoTable");
	var rows = obj.rows.length;
	var perfix = "row_";
	var checked = "0";

	for (var i=0; i<rows; i++){
		var s = i.toString();
		var name = perfix.concat(s);
		if(document.getElementById(name).checked==true){
			checked = "1";
			break;
		}
	}
	if(checked == "0"){
		alert("don't select a element!");
		return false;
	}
	*/
	obj.isclick = 1;
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	return true;
}

</SCRIPT>
<style>
.titleStyle{color:#0000FF}
.tableStyle{width:600px;border-width:0px;font-size:13px}
.tableTitle{border-width:0px;font-size:13px;font-style:italic;font-weight:bold}
.leftBlank{width:80px;border-width:0px;float:left;font-size:13px}
.topFrame{width:600px;border-width:0px;font-size:13px;font-weight:bold}
.rightFrame{width:520px;border-width:0px;float:right;font-size:13px}
.leftContent{width:120px;border-width:0px;text-align:left;font-size:13px}
.rightContent{width:400px;border-width:0px;text-align:left;font-size:13px}
.inputStyle{boder:1px solid #808080;font-size:12px;width:130px;height:20px}
.selectStyle{width:130px;}
.buttomStyle{width=100px;height:24px}
.infoTitle{font-size:13px;text-align:center;background-color:#808080;}
.infoContent{font-size:13px;text-align:center;background-color:#C0C0C0;}
.liststyle{width:600px;boder:1px dashed #808080;}
.leftHalf{width:50%;border-width:0px;float:left;font-size:14px}
.rightHalf{width:50%;border-width:0px;float:left;font-size:14px;text-align:right}
.clearfix:after {
content: ".";
display: block;
height: 0;
clear: both;
visibility: hidden;
}
.clearfix {display: inline-block;}
</style>
</head>

<body>
<div class="intro_main ">
	<p class="intro_title">IPsec VPN Configuration</p>
	<p class="intro_content"> This page is used to configure the parameters for IPsec mode VPN.</p>
</div>

<form action=/boaform/formIPsec method=POST name="ipsec">
<div class="data_common data_common_notitle">
	<table>
		<tr>
			<th>Negotiation Type</th>
			<td>
				<input name="negoType" type="radio" value="0" checked onClick="onClicknegoType()">Automatic&nbsp;
				<input name="negoType" type="radio" value="1" onClick="onClicknegoType()">Manual&nbsp;
			</td>
		</tr>
	</table>
</div>

<div class="column">
	<div id="manualHead" class="column_title">
		<div class="column_title_left"></div>
			<p>Manual Configure</p>
		<div class="column_title_right"></div>
	</div>
	<div id="autoHead" class="column_title">
		<div class="column_title_left"></div>
			<p>Auto Configure</p>
		<div class="column_title_right"></div>
	</div>
	<div class="data_common">
		<table>
			<tr>
				<th>&nbsp;&nbsp;Mode:</th>
				<td>
					<select name="transMode" onchange="onTransModeChange()">
							<option value="0" selected>Tunnel Mode</option>
							<option value="1">Transport Mode</option>
					</select>
				</td>
			</tr>
			<tr>
				<th colspan="2">Remote</th>
			</tr>
			<tr id="remoteTunnel">
				<th>&nbsp;&nbsp;Tunnel Addr:</th>
				<td>
					<input name="rtunnelAddr" type="text" value="0.0.0.0" onblur="checkit(this)" onfocus="clearit(this)" />
				</td>
			</tr>
			<tr id="remoteIntIP">
				<th>&nbsp;&nbsp;Internal IPaddr:</th>
				<td>
					<input name="remoteip" type="text" value="0.0.0.0" onblur="checkit(this)" onfocus="clearit(this)" />
				</td>
			</tr>
			<tr id="remoteMask">
				<th>&nbsp;&nbsp;Subnet Mask:</th>
				<td>
					<input name="remotemask" type="text"  value="255.255.255.0" onblur="checkit(this)" onfocus="clearit(this)" />
				</td>
			</tr>
			<tr>
				<th colspan="2">Local</th>
			</tr>
			<tr id="localTunnel">
				<th>&nbsp;&nbsp;Tunnel Addr:</th>
				<td>
					<input name="ltunnelAddr" type="text" value="0.0.0.0" onblur="checkit(this)" onfocus="clearit(this)" />
				</td>
			</tr>
			<tr id="localIntIP">
				<th>&nbsp;&nbsp;Internal IPaddr</th>
				<td>
					<input name="localip" type="text" value="0.0.0.0" onblur="checkit(this)" onfocus="clearit(this)" />
				</td>
			</tr>
			<tr id="localMask">
				<th>&nbsp;&nbsp;Subnet Mask</th>
				<td>
					<input name="localmask" type="text" value="255.255.255.0" onblur="checkit(this)" onfocus="clearit(this)" />
				</td>
			</tr>
			<tr>
				<th colspan="2">Security Option</th>
			</tr>
			<tr>
				<th>&nbsp;&nbsp;Encapsulation Type:</th>
				<td>
					<select name="encapsType" onchange="onEncapsTypeChange()">
							<option value="1" selected>ESP</option>
							<option value="2">AH</option>
							<option value="3">ESP+AH</option>
					</select>
				</td>
			</tr>
			<tbody id="pskTable">
				<tr>
					<th>&nbsp;&nbsp;IKE Auth Method:</th>
					<td>
						<select name="ikeAuthMethod" onchange="onIKEAuthMethodChange()">
								<option value="0" selected>Pre Shared Key</option>
								<option value="1">Certificate</option>
						</select>
					</td>
				</tr>
				<tr id = "psk_clumn">
					<th>&nbsp;&nbsp;Pre shared key:</th>
					<td>
						<input name="psk" type="text" />
					</td>
				</tr>
			</tbody>
			<tbody id="manualAlgorithms">
				<tr id="espEncr">
					<th>&nbsp;&nbsp;ESP Encrypt Algorithm:</th>
					<td>
						<select name="esp_e_algo" onchange="onESPEncryptChange()">
								<!--<option value="0">null_enc</option> -->
								<option value="1" selected>des-cbc</option>
								<option value="2">3des-cbc</option>
								<option value="3">aes-cbc</option>
						</select>
					</td>
				</tr>
				<tr id="espEncrKey">
					<th>&nbsp;&nbsp;ESP Encrypt Key:</th>
					<td>
						<input name="esp_ekey" type="text" />
					</td>
				</tr>
				<tr id="espAuth">
					<th>&nbsp;&nbsp;ESP Auth Algorithm:</th>
					<td>
						<select name="esp_a_algo" onchange="onESPAuthChange()">
								<!--<option value="0">non_auth</option> -->
								<option value="1" selected>hmac-md5</option>
								<option value="2">hmac-sha1</option>
						</select>
					</td>
				</tr>
				<tr id="espAuthKey">
					<th>&nbsp;&nbsp;ESP Auth Key:</th>
					<td>
						<input name="esp_akey" type="text" />
					</td>
				</tr>
				<tr id="ahAuth">
					<th>&nbsp;&nbsp;AH Auth Algorithm:</th>
					<td>
						<select name="ah_algo">
								<option value="1" selected>md5</option>
								<option value="2">sha1</option>
						</select>
					</td>
				</tr>
				<tr id="ahAuthKey">
					<th>&nbsp;&nbsp;AH Auth Key:</th>
					<td>
						<input name="ah_key" type="text" />
					</td>
				</tr>
				<tr>
					<th colspan="2">SPI Configration</th>
				</tr>
				<tr id="espSPI1">
					<th rowspan="2">&nbsp;&nbsp;ESP:</th>
					<td>
						outbound&nbsp;<input name="spi_out_esp" type="text" />
					</td>
				</tr>
				<tr id="espSPI2">
					<td>
						inbound&nbsp;&nbsp;<input name="spi_in_esp" type="text" />
					</td>
				</tr>
				<tr id="ahSPI1">
					<th rowspan="2">&nbsp;&nbsp;AH:</th>
					<td>
						outbound&nbsp;<input name="spi_out_ah" type="text" />
					</td>
				</tr>
				<tr id="ahSPI2">
					<td>
						inbound&nbsp;&nbsp;<input name="spi_in_ah" type="text" />
					</td>
				</tr>
			</tbody>
			<tr>
				<th>Advanced Option:</th>
				<td>
					<input name="advOption" type="checkbox" value="1" onClick="onClickAdvOption()" />
				</td>
			</tr>
			<tbody id="adv">
				<tr>
					<th colspan="2">Filter Option</th>
				</tr>
				<tr>
					<th>&nbsp;&nbsp;Protocol:</th>
					<td>
						<select name="filterProtocol" onChange=onProtocolChange()>
							<option value="0" selected>any</option>
							<option value="1">tcp</option>
							<option value="2">udp</option>
							<option value="3">icmp</option>
						</select>
					</td>
				</tr>
				<tr>
					<th>&nbsp;&nbsp;Port:</th>
					<td>
						<input name="filterPort" value="0" onblur="checkit(this)" onfocus="clearit(this)" type="text" />
					</td>
				</tr>
			</tbody>
			<tbody id="autoAdv">
				<tr>
					<th colspan="2">IKE Phase 1</th>
				</tr>
				<tr>
					<th>&nbsp;&nbsp;Negotiation Mode:</th>
					<td>
						<select name="negoMode">
							<option value="0" selected>main</option>
							<option value="1">aggressive</option>
						</select>
					</td>
				</tr>
				<tr>
					<th>&nbsp;&nbsp;Keepalive Time:</th>
					<td>
						<input  name="ikeAliveTime"class="inputStyle" value="28800" onblur="checkit(this)" onfocus="clearit(this)" type="text" />&nbsp;seconds
					</td>
				</tr>
				<tr>
					<th>&nbsp;&nbsp;IKE Algorithm 1:</th>
					<td>
						<select name="ikeProposal0">
							<% ipsec_ikePropList(); %>
						</select>
					</td>
				</tr>
				<tr>
					<th>&nbsp;&nbsp;IKE Algorithm 2:</th>
					<td>
						<select name="ikeProposal1">
							<% ipsec_ikePropList(); %>
						</select>
					</td>
				</tr>
				<tr>
					<th>&nbsp;&nbsp;IKE Algorithm 3:</th>
					<td>
						<select name="ikeProposal2">
							<% ipsec_ikePropList(); %>
						</select>
					</td>
				</tr>
				<tr>
					<th>&nbsp;&nbsp;IKE Algorithm 4:</th>
					<td>
						<select name="ikeProposal3">
							<% ipsec_ikePropList(); %>
						</select>
					</td>
				</tr>
				<tr>
					<th colspan="2">IKE Phase 2</th>
				</tr>
				<tr>
					<th>&nbsp;&nbsp;pfs_group mode:</th>
					<td>
						<select name="dhArray_p2">
							<option value="1" selected>modp768</option>
							<option value="2">modp1024</option>
						</select>
					</td>
				</tr>
				<tr id="encryptalgo_p2">
					<th>&nbsp;&nbsp;Encrypt Algorithm:</th>
					<td>
					<% ipsec_encrypt_p2List(); %>&nbsp;
					</td>
				</tr>
				<tr>
					<th>&nbsp;&nbsp;Auth Algorithm:</th>
					<td>
					<% ipsec_auth_p2List(); %>&nbsp;
					</td>
				</tr>
				<tr style="display:none">
					<td></td>
					<td>
						<input name="dhArray_p2" type="text" value="0" />
					</td>
				</tr>
				<tr style="display:none">
					<td></td>
					<td>
						<input name="encrypt_p2" type="text" value="0" />
					</td>
				</tr>
				<tr style="display:none">
					<td></td>
					<td>
						<input name="auth_p2" type="text" value="0" />
					</td>
				</tr>
				<tr>
					<th>&nbsp;&nbsp;Keepalive Time:</th>
					<td>
						<input name="saAliveTime" value="3600" onblur="checkit(this)" onfocus="clearit(this)" type="text" />&nbsp;seconds
					</td>
				</tr>
				<tr>
					<th>&nbsp;&nbsp;Keepalive Byte:</th>
					<td>
						<input name="saAliveByte" value="4194300" onblur="checkit(this)" onfocus="clearit(this)" type="text" />&nbsp;KB
					</td>
				</tr>
			</tbody>
		</table>
	</div>
</div>

<div class="btn_ctl">
	<input class="link_bg" name="saveConf" type="submit" value="Add/Save" onClick="return onClickSaveConfig(this)">
</div>

<div id="infoTable" class="column">
	<div class="column_title">
		<div class="column_title_left"></div>
			<p>IPsec Information List</p>
		<div class="column_title_right"></div>
	</div>
	<div class="data_common data_vertical">
		<table>
			<tr>
				<th>&nbsp;&nbsp;&nbsp;&nbsp;</th>
				<th>Enable</th>
				<th>State</th>
				<th>Type</th>
				<th>RemoteGW</th>
				<th>RemoteIP</th>
				<th>Interface</th>
				<th>LocalIP</th>
				<th>EncapMode</th>
				<th>filterProtocol</th>
				<th>filterPort</th>
			</tr>
			<% ipsec_infoList(); %>
		</table>
	</div>
</div>

<div class="btn_ctl">
	<input class="link_bg" name="delConf" type="submit" value="Delete Selected" onClick="return onClickChangeConfig(this)" />
	<input class="link_bg" name="enableConf" type="submit" value="Enable" onClick="return onClickChangeConfig(this)" />
	<input class="link_bg" name="disableConf" type="submit" value="Disable" onClick="return onClickChangeConfig(this)" />
</div>

<input name="submit-url" type="hidden" value="/ipsec.asp" />
<input type="hidden" name="postSecurityFlag" value="">
<script>
	ipsecSelection();
</script>
</form>

<div class="column">
	<div id="autoHead" class="column_title">
		<div class="column_title_left"></div>
			<p>Certificate Management</p>
		<div class="column_title_right"></div>
	</div>
	<div class="data_common">
		<table>
			<tr>
				<td>cert.pem</td>
				<td>
					<form action=/boaform/formIPSecCert method=POST enctype="multipart/form-data" name="ipsec_cert">
						<input type="file" value="Choose File" name="binary" size=24>&nbsp;&nbsp;
						<input class="inner_btn" type="submit" value="Upload" name="load">
					</form>
				</td>
			</tr>
			<tr>
				<td>privKey.pem</td>
				<td>
					<form action=/boaform/formIPSecKey method=POST enctype="multipart/form-data" name="ipsec_key">
						<input type="file" value="Choose File" name="binary" size=24>&nbsp;&nbsp;
						<input class="inner_btn" type="submit" value="Upload" name="load">
						<input type="hidden" name="postSecurityFlag" value="">
					</form>
				</td>
			</tr>
		</table>
	</div>
</div>
<br>
</body>
</html>
