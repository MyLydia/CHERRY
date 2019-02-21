<% SendWebHeadStr();%>
<title><% multilang(LANG_LAN_INTERFACE_SETTINGS); %></title>
<SCRIPT>
function resetClick()
{
	document.tcpip.reset;
}

function saveChanges()
{
	var lpm1 = 0;
	var lpm2 = 0;

	if (!checkHostIP(document.tcpip.ip, 1))
		return false;
	if (!checkNetmask(document.tcpip.mask, 1))
		return false;

	// Magician 2013/08/23: LAN port mask.
	with (document.forms[0])
	{
		if(typeof chk_port_mask1 != 'undefined' && chk_port_mask1 != null){
			for (var i = 0; i < chk_port_mask1.length; i++) {
				if (chk_port_mask1[i].checked == true)
					lpm1 |= (0x1 << i);
			}
			lan_port_mask1.value = lpm1;
		}
		if(typeof chk_port_mask2 != 'undefined' && chk_port_mask2 != null){
			for (var i = 0; i < chk_port_mask2.length; i++) {
				if (chk_port_mask2[i].checked == true)
					lpm2 |= (0x1 << i);
			}
			lan_port_mask2.value = lpm2;
		}

		if((ip_version1.selectedIndex != 0) && (ipv6_mode1[1].checked)){  //IPv6 enabled && mode is manual
			if (ipv6_addr1.value =="" || ipv6_addr1.value =="::") {
				alert("<% multilang(LANG_LAN_IPV6_ADDRESS_CANNOT_BE_EMPTY_FORMAT_IS_IPV6_ADDRESS_FOR_EXAMPLE_3FFE_501_FFFF_100_1); %>");
				ipv6_addr1.focus();
				return false;
			} else {
				if ( validateKeyV6IP(ipv6_addr1.value) == 0) {
					alert("<% multilang(LANG_INVALID_LAN_IPV6_IP); %>");
					ipv6_addr1.focus();
					return false;
				}
			}

			if (ipv6_prefix1.value =="") {
				alert("<% multilang(LANG_LAN_IPV6_ADDRESS_IPV6_PREFIX1_CANNOT_BE_EMPTY_VALID_NUMBER_IS_0_127); %>");
				ipv6_prefix1.focus();
				return false;
			} else {
				var prefixInt = parseInt(ipv6_prefix1.value);
				if ( prefixInt>127 ||prefixInt<0) {
					alert("<% multilang(LANG_INVALID_LAN_IPV6_PREVIX); %>");
					ipv6_prefix1.focus();
					return false;
				}
			}
		}
		save.isclick = 1;
	}
	// End Magician

	<% checkIP2(); %>
	
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);	
	return true;
}

function disableRadioGroup (radioArrOrButton)
{
  if (radioArrOrButton.type && radioArrOrButton.type == "radio") {
 	var radioButton = radioArrOrButton;
 	var radioArray = radioButton.form[radioButton.name];
  }
  else
 	var radioArray = radioArrOrButton;
 	radioArray.disabled = true;
 	for (var b = 0; b < radioArray.length; b++) {
 	if (radioArray[b].checked) {
 		radioArray.checkedElement = radioArray[b];
 		break;
	}
  }
  for (var b = 0; b < radioArray.length; b++) {
 	radioArray[b].disabled = true;
 	radioArray[b].checkedElement = radioArray.checkedElement;
  }
}

function updateState()
{
  if (document.tcpip.wlanDisabled.value == "ON") {

    disableRadioGroup(document.tcpip.BlockEth2Wir);

  }
}

function ipv6_mode1_change()
{
	with (document.forms[0])
	{
		if(ipv6_mode1[0].checked)
		{
			ipv6_addr1.disabled = true;
			ipv6_prefix1.disabled = true;
		}
		else
		{
			ipv6_addr1.disabled = false;
			ipv6_prefix1.disabled = false;

			if(ipv6_addr1.value =="::")
				ipv6_addr1.value ="";
		}
	}
}

function ipv6_mode2_change()
{
	with (document.forms[0])
	{
		if(ipv6_mode2[0].checked)
		{
			ipv6_addr2.disabled = true;
			ipv6_prefix2.disabled = true;
		}
		else
		{
			ipv6_addr2.disabled = false;
			ipv6_prefix2.disabled = false;
		}
	}
}

function ipv6_version1_change()
{
	with (document.forms[0])
	{
		if(ip_version1.selectedIndex == 0)
		{
			ipv6_mode1[0].disabled = true;
			ipv6_mode1[1].disabled = true;
			ipv6_addr1.disabled = true;
			ipv6_prefix1.disabled = true;
			ip.disabled = false;
			mask.disabled = false;
		}
		else
		{
			ipv6_mode1[0].disabled = false;
			ipv6_mode1[1].disabled = false;
			ipv6_addr1.disabled = false;
			ipv6_prefix1.disabled = false;
			ip.disabled = false;
			mask.disabled = false;
			ipv6_mode1_change();
		}
	}
}

<% DHCPClientScript(); %>
function on_init()
{
	ipv6_version1_change();
	updateDHCPClient();
}
<% lanScript(); %>
</SCRIPT>
</head>

<BODY onLoad="on_init();">
	<div class="intro_main ">
		<p class="intro_title"><% multilang(LANG_LAN_INTERFACE_SETTINGS); %></p>
		<p class="intro_content"><% multilang(LANG_PAGE_DESC_CONFIG_DEVICE_LAN_INTERFACE); %></p>
	</div>

	<form action=/boaform/formTcpipLanSetup method=POST name="tcpip">
		<div class="data_common data_common_notitle">
			<table>
				<input type=hidden name="wlanDisabled" value=<% wlanStatus(); %>>
				<tr>
				  <th width="30%"><% multilang(LANG_INTERFACE); %><% multilang(LANG_NAME); %>:</th>
				  <td width="70%">br0</td>
				</tr>
				<tr>
				  <th width="30%"><% multilang(LANG_IP_ADDRESS); %>:</th>
				  <td width="70%"><input type="text" name="ip" id="ip" size="15" maxlength="15" value=<% getInfo("lan-ip"); %>></td>
				</tr>
				<tr>
				  <th width="30%"><% multilang(LANG_SUBNET_MASK); %>:</th>
				  <td width="70%"><input type="text" name="mask" id="mask" size="15" maxlength="15" value="<% getInfo("lan-subnet"); %>"></td>
				</tr>
				<tr id=tr_ipv6_mode1 <% checkWrite("rg_only_function"); %>>
					<th width="30%"><% multilang(LANG_IPV6_ADDRESS_MODE); %>:</th>
					<td width="70%">
						<input type="radio" name="ipv6_mode1" value=0 OnChange="ipv6_mode1_change()" <% checkWrite("lan_ipv6_mode_auto"); %> ><% multilang(LANG_AUTO); %>
						<input type="radio" name="ipv6_mode1" value=1 OnChange="ipv6_mode1_change()" <% checkWrite("lan_ipv6_mode_manual"); %>><% multilang(LANG_MANUAL); %>
					</td>
				</tr>
				<tr id=tr_ipv6_addr1 <% checkWrite("rg_only_function"); %>>
				  <th width="30%"><% multilang(LANG_IPV6_ADDRESS); %>:</th>
				  <td width="70%"><input type="text" name="ipv6_addr1" size="30" maxlength="60" value=0></td>
				</tr>
				<tr id=tr_ipv6_prefix1 <% checkWrite("rg_only_function"); %>>
				  <th width="30%"><% multilang(LANG_IPV6_PREFIX_LENGTH); %>:</th>
				  <td width="70%"><input type="text" name="ipv6_prefix1" size="5" maxlength="5" value=0></td>
				</tr>
					<!-- Hide VID setting temporarily -->
				<tr style="display:none">
					<th width="30%"><% multilang(LANG_VLAN_ID); %>:</th>
					<td width="70%"><input type="text" name="lan_vlan_id1" size="15" maxlength="15" value="<% getInfo("lan_vlan_id1"); %>"></td>
				</tr>
				<tr <% checkWrite("rg_only_function"); %>>
					<th width="30%"><% multilang(LANG_IP_VERSION); %>:</th>
					<td width="70%">
						<select size="1" name="ip_version1" OnChange="ipv6_version1_change()">
							<option <% checkWrite("lan_ipverion_v4only"); %>  value="0">IPv4</option>
							<option <% checkWrite("lan_ipverion_v4v6"); %> value="2">IPv4/IPv6</option>
						</select>
					</td>
				</tr>
				<tr <% checkWrite("rg_only_function"); %>>
						<% lan_port_mask(); %>
				</tr>
			</table>
		</div>
		<% lan_setting(); %>

		<div class="btn_ctl">
			<input type="submit" value="<% multilang(LANG_APPLY_CHANGES); %>" name="save" onClick="return saveChanges()" class="link_bg">&nbsp;&nbsp;
			<!--input type="reset" value="Undo" name="reset" onClick="resetClick()"-->
			<input type="hidden" value="/tcpiplan.asp" name="submit-url">
			<input type="hidden" name="lan_port_mask1" value=0>
			<input type="hidden" name="lan_port_mask2" value=0>
			<input type="hidden" name="postSecurityFlag" value="">
		</div>
		<script>
		<% initPage("lan"); %>
		updateState();
		</script>
	</form>
<br><br>
</body>
</html>
