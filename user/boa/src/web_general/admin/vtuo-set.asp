<%SendWebHeadStr(); %>
<title>VTU-O Settings</title>

<SCRIPT>
/*
function line_onchange()
{
	document.set_vtuo_line.DSMaxSNR.disabled=document.set_vtuo_line.DSMaxSNRNoLmt.checked;
	document.set_vtuo_line.USMaxSNR.disabled=document.set_vtuo_line.USMaxSNRNoLmt.checked;
	document.set_vtuo_line.USMaxRxPwr.disabled=document.set_vtuo_line.USMaxRxPwrNoLmt.checked;
}
*/

function line_saveChanges(obj)
{
	obj.isclick = 1;
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	return true;
}

</SCRIPT>
</head>


<body>
<div class="intro_main ">
	<p class="intro_title">VTU-O Settings</p>
	<p class="intro_content"> This page is used to configure the parameters for VTU-O.</p>
</div>

<form action=/boaform/formSetVTUO method=POST name=set_vtuo_line>
<!--<h4>1. Line Profile Setup</h4>-->
<div class="data_common data_common_notitle">
	<table>
		<tr>
			<td width=50% align=left><h4>* Line Profile Setup</h4></td>
			<td width=25% align=left><h5><a href="/admin/vtuo-set-chan.asp"><i>Channel Profile</i><a></h5></td>
			<td width=25% align=left><h5><a href="/admin/vtuo-set-inm.asp"><i>INM Profile</i></a></h5></td>		
		</tr>
	</table>
</div>

<div class="data_common data_common_notitle">
	<table>
		<tr>
			<th align=left>VDSL2 Profile:</th>
			<td colspan=2>
				<input type=checkbox name=Vd2Prof35b>35b&nbsp;&nbsp;
				<input type=checkbox name=Vd2Prof30a>30a&nbsp;&nbsp;
				<input type=checkbox name=Vd2Prof17a>17a&nbsp;&nbsp;
				<input type=checkbox name=Vd2Prof12a>12a&nbsp;&nbsp;
				<input type=checkbox name=Vd2Prof12b>12b&nbsp;&nbsp;
				<input type=checkbox name=Vd2Prof8a>8a&nbsp;&nbsp;
				<input type=checkbox name=Vd2Prof8b>8b&nbsp;&nbsp;
				<input type=checkbox name=Vd2Prof8c>8c&nbsp;&nbsp;
				<input type=checkbox name=Vd2Prof8d>8d
			</td>
		</tr>

		<tr>
			<th align=left>ADSL Protocol:</th>
			<td colspan=2>
				<input type=checkbox name=AdProtG9921>G.992.1
				<input type=checkbox name=AdProtG9922>G.992.2
				<input type=checkbox name=AdProtG9923>G.992.3
				<input type=checkbox name=AdProtG9925>G.992.5
				<input type=checkbox name=AdProtANSI>ANSI T1.413
				<input type=checkbox name=AdProtETSI>ETSI TS101 388
			</td>
		</tr>

		<tr>
			<th align=left></th>
			<th align=center>Downstream</th>
			<th align=center>Upstream</th>
		</tr>

		<tr>
			<th align=left>Max SNR Margin</th>
			<td>
				<input type="text" name="DSMaxSNR" size="8" maxlength="8" value="">dB
	<!--
				<input type=checkbox name=DSMaxSNRNoLmt onClick="line_onchange()">No Limit
	-->
			</td>
			<td>
				<input type="text" name="USMaxSNR" size="8" maxlength="8" value="">dB
	<!--
				<input type=checkbox name=USMaxSNRNoLmt onClick="line_onchange()">No Limit
	-->
			</td>
		</tr>

		<tr>
			<th align=left>Target SNR Margin</th>
			<td>
				<input type="text" name="DSTargetSNR" size="8" maxlength="8" value="">dB
			</td>
			<td>
				<input type="text" name="USTargetSNR" size="8" maxlength="8" value="">dB
			</td>
		</tr>

		<tr>
			<th align=left>Min SNR Margin</th>
			<td>
				<input type="text" name="DSMinSNR" size="8" maxlength="8" value="">dB
			</td>
			<td>
				<input type="text" name="USMinSNR" size="8" maxlength="8" value="">dB
			</td>
		</tr>

		<tr>
			<th align=left>OLR</th>
			<td>
				<input type="radio" name="DSBitswap" value=0 >Off&nbsp;&nbsp;
				<input type="radio" name="DSBitswap" value=1 >On&nbsp;&nbsp;
			</td>
			<td>
				<input type="radio" name="USBitswap" value=0 >Off&nbsp;&nbsp;
				<input type="radio" name="USBitswap" value=1 >On&nbsp;&nbsp;
			</td>
		</tr>

		<tr>
			<th align=left>
				OLR Option&nbsp;&nbsp;
				<a href="/admin/vtuo-set-sra.asp"><i>[ Edit ]</i>&nbsp;</a>
			</th>
			<td id="LineSRAModeDs" >
			</td>
			<td id="LineSRAModeUs" >
			</td>
		</tr>

		<tr>
			<th align=left>PSD Control</th>
			<th align=center>Downstream</th>
			<th align=center>Upstream</th>
		</tr>

		<tr>
			<th align=left>
				MIB PSD Mask&nbsp;&nbsp;
				<a href="/admin/vtuo-set-psd.asp"><i>[ Edit ]</i>&nbsp;</a>
			</th>
			<td id="LineMibPsdDs" >
			</td>
			<td id="LineMibPsdUs" >
			</td>
		</tr>

		<tr>
			<th align=left>US0</th>
			<td></td>
			<td>
				<input type="radio" name="US0" value=0 >Disable&nbsp;&nbsp;
				<input type="radio" name="US0" value=1 >Allow&nbsp;&nbsp;
			</td>
		</tr>

		<tr>
			<th align=left>US0 Mask</th>
			<td></td>
			<td>
				<select size=1 name="US0Mask">
					<option value=0>EU-32</option>
					<option value=1>EU-36</option>
					<option value=2>EU-40</option>
					<option value=3>EU-44</option>
					<option value=4>EU-48</option>
					<option value=5>EU-52</option>
					<option value=6>EU-56</option>
					<option value=7>EU-60</option>
					<option value=8>EU-64</option>
					<option value=9>EU-128</option>
				</select>
			</td>
		</tr>

		<tr>
			<th align=left>UPBO</th>
			<td></td>
			<td>
				<table border=0 cellspacing=4 cellpadding=0>
				<tr>
					<td width=33%>
						<input type="radio" name="UPBO" value=0 >Disable
					</td>
					<td width=33%>
						<input type="radio" name="UPBO" value=1 >Auto
					</td>
					<td>
						<input type="radio" name="UPBO" value=2 >Override
					</td>
				</tr>
				<tr>
					<td>UPBOKL</td>
					<td colspan=2>
						<input type="text" name="UPBOKL" size="8" maxlength="8" value="">dB
					</td>
				</tr>
				<tr>
					<td></td>
					<td align=center>A</td>
					<td align=center>B</td>
				</tr>
				<tr>
					<td>US Band 1</td>
					<td><input type="text" name="USBand1a" size="8" maxlength="8" value=""></td>
					<td><input type="text" name="USBand1b" size="8" maxlength="8" value=""></td>
				</tr>
				<tr>
					<td>US Band 2</td>
					<td><input type="text" name="USBand2a" size="8" maxlength="8" value=""></td>
					<td><input type="text" name="USBand2b" size="8" maxlength="8" value=""></td>
				</tr>
				<tr>
					<td>US Band 3</td>
					<td><input type="text" name="USBand3a" size="8" maxlength="8" value=""></td>
					<td><input type="text" name="USBand3b" size="8" maxlength="8" value=""></td>
				</tr>
				<tr>
					<td>US Band 4</td>
					<td><input type="text" name="USBand4a" size="8" maxlength="8" value=""></td>
					<td><input type="text" name="USBand4b" size="8" maxlength="8" value=""></td>
				</tr>
				</table>
			</td>
		</tr>

		<tr>
			<th align=left>DS1 Mask</th>
			<td>
				<select size=1 name="LimitMask">
					<option value=0>D-32</option>
					<option value=1>D-48</option>
					<option value=2>D-64</option>
					<option value=3>D-128</option>
				</select>
			</td>
			<td></td>
		</tr>

		<tr>
			<th align=left>
				DPBO&nbsp;&nbsp;
				<a href="/admin/vtuo-set-dpbo.asp"><i>[ Edit ]</i>&nbsp;</a>
			</th>
			<td id="LineDpboEnable" >
			</td>
			<td></td>
		</tr>
	<!--
		<tr>
			<th align=left>Max Rx Power</th>
			<td></td>
			<td>
				<input type="text" name="USMaxRxPwr" size="8" maxlength="8" value="">dBm
				<input type=checkbox name=USMaxRxPwrNoLmt onClick="line_onchange()">No Limit
			</td>
		</tr>

		<tr>
			<th align=left>Max Tx Power</th>
			<td>
				<input type="text" name="DSMaxTxPwr" size="8" maxlength="8" value="">dBm
			</td>
			<td>
				<input type="text" name="USMaxTxPwr" size="8" maxlength="8" value="">dBm
			</td>
		</tr>

		<tr>
			<th align=left>Min Overhead Rate</th>
			<td>
				<input type="text" name="DSMinOhRate" size="8" maxlength="8" value="">kbps
			</td>
			<td>
				<input type="text" name="USMinOhRate" size="8" maxlength="8" value="">kbps
			</td>
		</tr>

		<tr>
			<th align=left>Limit PSD Mask</th>
			<td colspan=2>
				<table border=0 cellspacing=4 cellpadding=0>
				<tr>
					<td>Transmission Mode</td>
					<td>
						<select size=1 name="TransMode">
							<option value=0>G.993.2 Annex A</option>
						</select>
					</td>
				</tr>

				<tr>
					<td>Class Mask</td>
					<td>
						<select size=1 name="ClassMask">
							<option value=0>998</option>
							<option value=1>997</option>
						</select>
					</td>
				</tr>
				</table>
			</td>
		</tr>

		<tr>
			<th align=left>Retrain Mode</th>
			<td colspan=2>
				<input type=checkbox name=RTMode>Auto
			</td>
		</tr>

		<tr>
			<th align=left>
				Virtual Noise&nbsp;&nbsp;
				<a href="/admin/vtuo-set-vn.asp"><i>[ Edit ]</i>&nbsp;</a>
			</th>
			<td id="LineVNDs" >
			</td>
			<td id="LineVNUs" >
			</td>
		</tr>

		<tr>
			<th align=left>
				RFI Band&nbsp;&nbsp;
				<a href="/admin/vtuo-set-rfi.asp"><i>[ Edit ]</i>&nbsp;</a>
			</th>
			<td colspan=2 id="LineRfi" >
			</td>
		</tr>
	-->
	</table>
</div>

<div class="btn_ctl">
	<input class="link_bg" type=submit value="Apply Changes" name="LineProfile" onClick="return line_saveChanges(this)">
	<input type=hidden value="/admin/vtuo-set.asp" name="submit-url">
	<input type="hidden" name="postSecurityFlag" value="">
</div>
<% vtuo_checkWrite("line-init"); %>
<!--
<script>
line_onchange();
</script>
-->

</form>

<br><br>
</body>
</html>
