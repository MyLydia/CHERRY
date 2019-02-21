<%SendWebHeadStr(); %>
<title>VTU-O Settings</title>

<SCRIPT>
function sra_saveChanges(obj)
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

<form action=/boaform/formSetVTUO method=POST name=set_vtuo_sra>
<div class="column">
	<div class="column_title">
		<div class="column_title_left"></div>
			<p>* Line Profile &nbsp;&gt;&nbsp; OLR Option Setup</p>
		<div class="column_title_right"></div>
	</div>
	<div class="data_common data_vertical">
		<table>
			<tr>
				<th align=left></th>
				<th align=center>Downstream</th>
				<th align=center>Upstream</th>
			</tr>
			<tr>
				<th align=left>Rate Adaptive</th>
				<td>
					<input type="radio" name="DSRateAdapt" value=0 >Manual&nbsp;&nbsp;
					<input type="radio" name="DSRateAdapt" value=1 >AdaptInit&nbsp;&nbsp;
					<input type="radio" name="DSRateAdapt" value=2 >Dynamic&nbsp;&nbsp;
					<input type="radio" name="DSRateAdapt" value=3 >SOS&nbsp;&nbsp;
				</td>
				<td>
					<input type="radio" name="USRateAdapt" value=0 >Manual&nbsp;&nbsp;
					<input type="radio" name="USRateAdapt" value=1 >AdaptInit&nbsp;&nbsp;
					<input type="radio" name="USRateAdapt" value=2 >Dynamic&nbsp;&nbsp;
					<input type="radio" name="USRateAdapt" value=3 >SOS&nbsp;&nbsp;
				</td>
			</tr>
			<tr>
				<th align=left>Dynamic Depth</th>
				<td>
					<input type="radio" name="DSDynDep" value=0 >Disable&nbsp;&nbsp;
					<input type="radio" name="DSDynDep" value=1 >Enable&nbsp;&nbsp;
				</td>
				<td>
					<input type="radio" name="USDynDep" value=0 >Disable&nbsp;&nbsp;
					<input type="radio" name="USDynDep" value=1 >Enable&nbsp;&nbsp;
				</td>
			</tr>
			<tr>
				<th align=left>RA_USNRM (dB)</th>
				<td><input type="text" name="DSUpShiftSNR" size="8" maxlength="8" value=""></td>
				<td><input type="text" name="USUpShiftSNR" size="8" maxlength="8" value=""></td>
			</tr>
			<tr>
				<th align=left>RA_UTIME (sec)</th>
				<td><input type="text" name="DSUpShiftTime" size="8" maxlength="8" value=""></td>
				<td><input type="text" name="USUpShiftTime" size="8" maxlength="8" value=""></td>
			</tr>
			<tr>
				<th align=left>RA_DSNRM (dB)</th>
				<td><input type="text" name="DSDownShiftSNR" size="8" maxlength="8" value=""></td>
				<td><input type="text" name="USDownShiftSNR" size="8" maxlength="8" value=""></td>
			</tr>
			<tr>
				<th align=left>RA_DTIME (sec)</th>
				<td><input type="text" name="DSDownShiftTime" size="8" maxlength="8" value=""></td>
				<td><input type="text" name="USDownShiftTime" size="8" maxlength="8" value=""></td>
			</tr>
			<!--<tr>
				<td>&nbsp;</td>
				<td>&nbsp;</td>
				<td>&nbsp;</td>
			</tr>-->
			<tr>
				<th align=left>SOS-TIME (ms)</th>
				<td><input type="text" name="DSSosTime" size="8" maxlength="8" value=""></td>
				<td><input type="text" name="USSosTime" size="8" maxlength="8" value=""></td>
			</tr>
			<tr>
				<th align=left>SOS-CRC</th>
				<td><input type="text" name="DSSosCrc" size="8" maxlength="8" value=""></td>
				<td><input type="text" name="USSosCrc" size="8" maxlength="8" value=""></td>
			</tr>
			<tr>
				<th align=left>SOS-NTONES (%)</th>
				<td><input type="text" name="DSSosnTones" size="8" maxlength="8" value=""></td>
				<td><input type="text" name="USSosnTones" size="8" maxlength="8" value=""></td>
			</tr>
			<tr>
				<th align=left>MAX-SOS</th>
				<td><input type="text" name="DSSosMax" size="8" maxlength="8" value=""></td>
				<td><input type="text" name="USSosMax" size="8" maxlength="8" value=""></td>
			</tr>
			<!--
			<tr>
				<th align=left>SOS Multi-Step Tones</th>
				<td>
					<select size=1 name="DSSosMultiStep" disabled>
						<option  value=0>all</option>
					</select>
					tones
				</td>
				<td>
					<select size=1 name="USSosMultiStep" disabled>
						<option  value=0>all</option>
					</select>
					tones
				</td>
			</tr>
			-->
			<!--<tr>
				<td>&nbsp;</td>
				<td>&nbsp;</td>
				<td>&nbsp;</td>
			</tr>-->
			<tr>
				<th align=left>ROC Enable</th>
				<td>
					<input type="radio" name="DSRocEnable" value=0 >Disable&nbsp;&nbsp;
					<input type="radio" name="DSRocEnable" value=1 >Enable&nbsp;&nbsp;
				</td>
				<td>
					<input type="radio" name="USRocEnable" value=0 >Disable&nbsp;&nbsp;
					<input type="radio" name="USRocEnable" value=1 >Enable&nbsp;&nbsp;
				</td>
			</tr>
			<tr>
				<th align=left>SNRMOFFSET-ROC (dB)</th>
				<td><input type="text" name="DSRocSNR" size="8" maxlength="8" value=""></td>
				<td><input type="text" name="USRocSNR" size="8" maxlength="8" value=""></td>
			</tr>

			<tr>
				<th align=left>INPMIN-ROC (dB)</th>
				<td>
					<select size=1 name="DSRocMinINP">
						<option value=0>0</option>
						<option value=1>1</option>
						<option value=2>2</option>
						<option value=3>3</option>
						<option value=4>4</option>
						<option value=5>5</option>
						<option value=6>6</option>
						<option value=7>7</option>
						<option value=8>8</option>
						<option value=9>9</option>
						<option value=10>10</option>
						<option value=11>11</option>
						<option value=12>12</option>
						<option value=13>13</option>
						<option value=14>14</option>
						<option value=15>15</option>
						<option value=16>16</option>
					</select>
				</td>
				<td>
					<select size=1 name="USRocMinINP">
						<option value=0>0</option>
						<option value=1>1</option>
						<option value=2>2</option>
						<option value=3>3</option>
						<option value=4>4</option>
						<option value=5>5</option>
						<option value=6>6</option>
						<option value=7>7</option>
						<option value=8>8</option>
						<option value=9>9</option>
						<option value=10>10</option>
						<option value=11>11</option>
						<option value=12>12</option>
						<option value=13>13</option>
						<option value=14>14</option>
						<option value=15>15</option>
						<option value=16>16</option>
					</select>
				</td>
			</tr>
		</table>
	</div>
</div>

<div class="btn_ctl">
	<input class="link_bg" type=submit value="Apply Changes" name="SraSetup" onClick="return sra_saveChanges(this)">
	&nbsp;&nbsp;&nbsp;
	<input class="link_bg" type=button value="Back" onclick="location.assign('/admin/vtuo-set.asp')">
	<input type=hidden value="/admin/vtuo-set-sra.asp" name="submit-url">
	<input type="hidden" name="postSecurityFlag" value="">
</div>
<% vtuo_checkWrite("sra-init"); %>
</form>
<br>
<br>
</body>
</html>
