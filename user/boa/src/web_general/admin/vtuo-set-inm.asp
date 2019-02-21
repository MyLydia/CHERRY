<%SendWebHeadStr(); %>
<title>VTU-O Settings</title>

<SCRIPT>
function inm_saveChanges(obj)
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

<form action=/boaform/formSetVTUO method=POST name=set_vtuo_inm>
<!--<h4>3. Impulse Noise Moniter Setup</h4>-->
<div class="data_common data_common_notitle">
	<table>
		<tr>
			<td width=50% align=left><h4>* Impulse Noise Moniter Setup</h4></td>
			<td width=25% align=left><h5><a href="/admin/vtuo-set.asp"><i>Line Profile</i><a></h5></td>
			<td width=25% align=left><h5><a href="/admin/vtuo-set-chan.asp"><i>Channel Profile</i></a></h5></td>		
		</tr>
	</table>
</div>

<div class="data_vertical data_common_notitle">
	<div class="data_common ">
		<table>
			<tr>
				<th width=33% align=left></th>
				<th width=33% align=center>NearEnd</th>
				<th width=34% align=center>FarEnd</th>
			</tr>
			<tr>
				<th align=left>InpEqMode</th>
				<td>
					<select size=1 name="NEInpEqMode">
						<option value=0>0</option>
						<option value=1>1</option>
						<option value=2>2</option>
						<option value=3>3</option>
					</select>
				</td>
				<td>
					<select size=1 name="FEInpEqMode">
						<option value=0>0</option>
						<option value=1>1</option>
						<option value=2>2</option>
						<option value=3>3</option>
					</select>
				</td>
			</tr>
			<tr>
				<th align=left>INMCC</th>
				<td>
					<input type="text" name="NEInmCc" size="8" maxlength="8" value="">symbol
				</td>
				<td>
					<input type="text" name="FEInmCc" size="8" maxlength="8" value="">symbol
				</td>
			</tr>
			<tr>
				<th align=left>IAT Offset</th>
				<td>
					<input type="text" name="NEIatOff" size="8" maxlength="8" value="">symbol
				</td>
				<td>
					<input type="text" name="FEIatOff" size="8" maxlength="8" value="">symbol
				</td>
			</tr>
			<tr>
				<th align=left>IAT Setup</th>
				<td>
					<input type="text" name="NEIatSet" size="8" maxlength="8" value="">symbol
				</td>
				<td>
					<input type="text" name="FEIatSet" size="8" maxlength="8" value="">symbol
				</td>
			</tr>
			<!--
			<tr>
				<th align=left>ISDD Sensitivity</th>
				<td>
					<input type="text" name="NEIsddSen" size="8" maxlength="8" value="">dB
				</td>
				<td>
					<input type="text" name="FEIsddSen" size="8" maxlength="8" value="" disabled>dB
				</td>
			</tr>
			-->
		</table>
	</div>
</div>

<div class="btn_ctl">
	<input class="link_bg" type=submit value="Apply Changes" name="InmSetup" onClick="return inm_saveChanges(this)">
	<input type=hidden value="/admin/vtuo-set-inm.asp" name="submit-url">
	<input type="hidden" name="postSecurityFlag" value="">
</div>
<% vtuo_checkWrite("inm-init"); %>
</form>
<br><br>
</body>
</html>
