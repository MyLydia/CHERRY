<%SendWebHeadStr(); %>
<title>VTU-O Settings</title>

<SCRIPT>
function rfi_saveChanges(obj)
{
	obj.isclick = 1;
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	return true;
}

function rfi_load_clear()
{
	document.set_vtuo_rfi.ToneId1.value='0';
	document.set_vtuo_rfi.ToneId2.value='0';
	document.set_vtuo_rfi.ToneId3.value='0';
	document.set_vtuo_rfi.ToneId4.value='0';
	document.set_vtuo_rfi.ToneId5.value='0';
	document.set_vtuo_rfi.ToneId6.value='0';
	document.set_vtuo_rfi.ToneId7.value='0';
	document.set_vtuo_rfi.ToneId8.value='0';
	document.set_vtuo_rfi.ToneId9.value='0';
	document.set_vtuo_rfi.ToneId10.value='0';

	document.set_vtuo_rfi.ToneId11.value='0';
	document.set_vtuo_rfi.ToneId12.value='0';
	document.set_vtuo_rfi.ToneId13.value='0';
	document.set_vtuo_rfi.ToneId14.value='0';
	document.set_vtuo_rfi.ToneId15.value='0';
	document.set_vtuo_rfi.ToneId16.value='0';

	document.set_vtuo_rfi.ToneIdEnd1.value='0';
	document.set_vtuo_rfi.ToneIdEnd2.value='0';
	document.set_vtuo_rfi.ToneIdEnd3.value='0';
	document.set_vtuo_rfi.ToneIdEnd4.value='0';
	document.set_vtuo_rfi.ToneIdEnd5.value='0';
	document.set_vtuo_rfi.ToneIdEnd6.value='0';
	document.set_vtuo_rfi.ToneIdEnd7.value='0';
	document.set_vtuo_rfi.ToneIdEnd8.value='0';
	document.set_vtuo_rfi.ToneIdEnd9.value='0';
	document.set_vtuo_rfi.ToneIdEnd10.value='0';

	document.set_vtuo_rfi.ToneIdEnd11.value='0';
	document.set_vtuo_rfi.ToneIdEnd12.value='0';
	document.set_vtuo_rfi.ToneIdEnd13.value='0';
	document.set_vtuo_rfi.ToneIdEnd14.value='0';
	document.set_vtuo_rfi.ToneIdEnd15.value='0';
	document.set_vtuo_rfi.ToneIdEnd16.value='0';

}
function rfi_load_mib()
{
<% vtuo_checkWrite("rfi-init-tbl"); %>
}

function rfi_freq( id )
{
	var frequnit=43125;
	var new_freq, new_freq1,new_freq2;
	var str_freq;

	new_freq = frequnit*id;
	new_freq2 = new_freq % 10000;
	new_freq1 = (new_freq-new_freq2) / 10000;
	if(new_freq2==0)
		str_freq = new_freq1.toString() + '.0000';
	else if(new_freq2<10)
		str_freq = new_freq1.toString() + '.000' + new_freq2.toString();
	else if(new_freq2<100)
		str_freq = new_freq1.toString() + '.00' + new_freq2.toString();
	else if(new_freq2<1000)
		str_freq = new_freq1.toString() + '.0' + new_freq2.toString();
	else
		str_freq = new_freq1.toString() + '.' + new_freq2.toString();
	
	return str_freq;
}
function rfi_update_freq()
{
document.set_vtuo_rfi.Freq1.value=rfi_freq(document.set_vtuo_rfi.ToneId1.value);
document.set_vtuo_rfi.Freq2.value=rfi_freq(document.set_vtuo_rfi.ToneId2.value);
document.set_vtuo_rfi.Freq3.value=rfi_freq(document.set_vtuo_rfi.ToneId3.value);
document.set_vtuo_rfi.Freq4.value=rfi_freq(document.set_vtuo_rfi.ToneId4.value);
document.set_vtuo_rfi.Freq5.value=rfi_freq(document.set_vtuo_rfi.ToneId5.value);
document.set_vtuo_rfi.Freq6.value=rfi_freq(document.set_vtuo_rfi.ToneId6.value);
document.set_vtuo_rfi.Freq7.value=rfi_freq(document.set_vtuo_rfi.ToneId7.value);
document.set_vtuo_rfi.Freq8.value=rfi_freq(document.set_vtuo_rfi.ToneId8.value);
document.set_vtuo_rfi.Freq9.value=rfi_freq(document.set_vtuo_rfi.ToneId9.value);
document.set_vtuo_rfi.Freq10.value=rfi_freq(document.set_vtuo_rfi.ToneId10.value);

document.set_vtuo_rfi.Freq11.value=rfi_freq(document.set_vtuo_rfi.ToneId11.value);
document.set_vtuo_rfi.Freq12.value=rfi_freq(document.set_vtuo_rfi.ToneId12.value);
document.set_vtuo_rfi.Freq13.value=rfi_freq(document.set_vtuo_rfi.ToneId13.value);
document.set_vtuo_rfi.Freq14.value=rfi_freq(document.set_vtuo_rfi.ToneId14.value);
document.set_vtuo_rfi.Freq15.value=rfi_freq(document.set_vtuo_rfi.ToneId15.value);
document.set_vtuo_rfi.Freq16.value=rfi_freq(document.set_vtuo_rfi.ToneId16.value);


document.set_vtuo_rfi.FreqEnd1.value=rfi_freq(document.set_vtuo_rfi.ToneIdEnd1.value);
document.set_vtuo_rfi.FreqEnd2.value=rfi_freq(document.set_vtuo_rfi.ToneIdEnd2.value);
document.set_vtuo_rfi.FreqEnd3.value=rfi_freq(document.set_vtuo_rfi.ToneIdEnd3.value);
document.set_vtuo_rfi.FreqEnd4.value=rfi_freq(document.set_vtuo_rfi.ToneIdEnd4.value);
document.set_vtuo_rfi.FreqEnd5.value=rfi_freq(document.set_vtuo_rfi.ToneIdEnd5.value);
document.set_vtuo_rfi.FreqEnd6.value=rfi_freq(document.set_vtuo_rfi.ToneIdEnd6.value);
document.set_vtuo_rfi.FreqEnd7.value=rfi_freq(document.set_vtuo_rfi.ToneIdEnd7.value);
document.set_vtuo_rfi.FreqEnd8.value=rfi_freq(document.set_vtuo_rfi.ToneIdEnd8.value);
document.set_vtuo_rfi.FreqEnd9.value=rfi_freq(document.set_vtuo_rfi.ToneIdEnd9.value);
document.set_vtuo_rfi.FreqEnd10.value=rfi_freq(document.set_vtuo_rfi.ToneIdEnd10.value);

document.set_vtuo_rfi.FreqEnd11.value=rfi_freq(document.set_vtuo_rfi.ToneIdEnd11.value);
document.set_vtuo_rfi.FreqEnd12.value=rfi_freq(document.set_vtuo_rfi.ToneIdEnd12.value);
document.set_vtuo_rfi.FreqEnd13.value=rfi_freq(document.set_vtuo_rfi.ToneIdEnd13.value);
document.set_vtuo_rfi.FreqEnd14.value=rfi_freq(document.set_vtuo_rfi.ToneIdEnd14.value);
document.set_vtuo_rfi.FreqEnd15.value=rfi_freq(document.set_vtuo_rfi.ToneIdEnd15.value);
document.set_vtuo_rfi.FreqEnd16.value=rfi_freq(document.set_vtuo_rfi.ToneIdEnd16.value);

}

function rfi_init()
{
	rfi_load_clear();
	rfi_load_mib();
	rfi_update_freq();	
}

</SCRIPT>
</head>


<body>
<div class="intro_main ">
	<p class="intro_title">VTU-O Settings</p>
	<p class="intro_content"> This page is used to configure the parameters for VTU-O.</p>
</div>

<form action=/boaform/formSetVTUO method=POST name=set_vtuo_rfi>
<div class="column">
	<div class="column_title">
		<div class="column_title_left"></div>
			<p>* Line Profile &nbsp;&gt;&nbsp; RFI Setup</p>
		<div class="column_title_right"></div>
	</div>
	<div class="data_common data_vertical">
		<table>
			<tr>
		 		<th></th>
		 		<th colspan=2 align=center>Start</th>
				<th colspan=2 align=center>Stop</th>
			</tr>
			<tr>
				<th align=center>Band</th>
				<th align=center>Tone Index</th>
				<th align=center>Frequency<br>(kHz)</th>

				<th align=center>Tone Index</th>
				<th align=center>Frequency<br>(kHz)</th>
			</tr>
			<tr>
				<th align=center>1</th>
				<td>
					<input type="text" name="ToneId1" size="8" maxlength="8" value="" onchange="rfi_update_freq()">
				</td>
				<td>
					<input type="text" name="Freq1" size="16" maxlength="16" value="" disabled>
				</td>
				<td>
					<input type="text" name="ToneIdEnd1" size="8" maxlength="8" value="" onchange="rfi_update_freq()">
				</td>
				<td>
					<input type="text" name="FreqEnd1" size="16" maxlength="16" value="" disabled>
				</td>
			</tr>
			<tr>
				<th align=center>2</th>
				<td>
					<input type="text" name="ToneId2" size="8" maxlength="8" value="" onchange="rfi_update_freq()">
				</td>
				<td>
					<input type="text" name="Freq2" size="16" maxlength="16" value="" disabled>
				</td>
				<td>
					<input type="text" name="ToneIdEnd2" size="8" maxlength="8" value="" onchange="rfi_update_freq()">
				</td>
				<td>
					<input type="text" name="FreqEnd2" size="16" maxlength="16" value="" disabled>
				</td>
			</tr>
			<tr>
				<th align=center>3</th>
				<td>
					<input type="text" name="ToneId3" size="8" maxlength="8" value="" onchange="rfi_update_freq()">
				</td>
				<td>
					<input type="text" name="Freq3" size="16" maxlength="16" value="" disabled>
				</td>
				<td>
					<input type="text" name="ToneIdEnd3" size="8" maxlength="8" value="" onchange="rfi_update_freq()">
				</td>
				<td>
					<input type="text" name="FreqEnd3" size="16" maxlength="16" value="" disabled>
				</td>
			</tr>
			<tr>
				<th align=center>4</th>
				<td>
					<input type="text" name="ToneId4" size="8" maxlength="8" value="" onchange="rfi_update_freq()">
				</td>
				<td>
					<input type="text" name="Freq4" size="16" maxlength="16" value="" disabled>
				</td>
				<td>
					<input type="text" name="ToneIdEnd4" size="8" maxlength="8" value="" onchange="rfi_update_freq()">
				</td>
				<td>
					<input type="text" name="FreqEnd4" size="16" maxlength="16" value="" disabled>
				</td>
			</tr>
			<tr>
				<th align=center>5</th>
				<td>
					<input type="text" name="ToneId5" size="8" maxlength="8" value="" onchange="rfi_update_freq()">
				</td>
				<td>
					<input type="text" name="Freq5" size="16" maxlength="16" value="" disabled>
				</td>
				<td>
					<input type="text" name="ToneIdEnd5" size="8" maxlength="8" value="" onchange="rfi_update_freq()">
				</td>
				<td>
					<input type="text" name="FreqEnd5" size="16" maxlength="16" value="" disabled>
				</td>
			</tr>
			<tr>
				<th align=center>6</th>
				<td>
					<input type="text" name="ToneId6" size="8" maxlength="8" value="" onchange="rfi_update_freq()">
				</td>
				<td>
					<input type="text" name="Freq6" size="16" maxlength="16" value="" disabled>
				</td>
				<td>
					<input type="text" name="ToneIdEnd6" size="8" maxlength="8" value="" onchange="rfi_update_freq()">
				</td>
				<td>
					<input type="text" name="FreqEnd6" size="16" maxlength="16" value="" disabled>
				</td>
			</tr>
			<tr>
				<th align=center>7</th>
				<td>
					<input type="text" name="ToneId7" size="8" maxlength="8" value="" onchange="rfi_update_freq()">
				</td>
				<td>
					<input type="text" name="Freq7" size="16" maxlength="16" value="" disabled>
				</td>
				<td>
					<input type="text" name="ToneIdEnd7" size="8" maxlength="8" value="" onchange="rfi_update_freq()">
				</td>
				<td>
					<input type="text" name="FreqEnd7" size="16" maxlength="16" value="" disabled>
				</td>
			</tr>
			<tr>
				<th align=center>8</th>
				<td>
					<input type="text" name="ToneId8" size="8" maxlength="8" value="" onchange="rfi_update_freq()">
				</td>
				<td>
					<input type="text" name="Freq8" size="16" maxlength="16" value="" disabled>
				</td>
				<td>
					<input type="text" name="ToneIdEnd8" size="8" maxlength="8" value="" onchange="rfi_update_freq()">
				</td>
				<td>
					<input type="text" name="FreqEnd8" size="16" maxlength="16" value="" disabled>
				</td>
			</tr>
			<tr>
				<th align=center>9</th>
				<td>
					<input type="text" name="ToneId9" size="8" maxlength="8" value="" onchange="rfi_update_freq()">
				</td>
				<td>
					<input type="text" name="Freq9" size="16" maxlength="16" value="" disabled>
				</td>
				<td>
					<input type="text" name="ToneIdEnd9" size="8" maxlength="8" value="" onchange="rfi_update_freq()">
				</td>
				<td>
					<input type="text" name="FreqEnd9" size="16" maxlength="16" value="" disabled>
				</td>
			</tr>
			<tr>
				<th align=center>10</th>
				<td>
					<input type="text" name="ToneId10" size="8" maxlength="8" value="" onchange="rfi_update_freq()">
				</td>
				<td>
					<input type="text" name="Freq10" size="16" maxlength="16" value="" disabled>
				</td>
				<td>
					<input type="text" name="ToneIdEnd10" size="8" maxlength="8" value="" onchange="rfi_update_freq()">
				</td>
				<td>
					<input type="text" name="FreqEnd10" size="16" maxlength="16" value="" disabled>
				</td>
			</tr>

			<tr>
				<th align=center>11</th>
				<td>
					<input type="text" name="ToneId11" size="8" maxlength="8" value="" onchange="rfi_update_freq()">
				</td>
				<td>
					<input type="text" name="Freq11" size="16" maxlength="16" value="" disabled>
				</td>
				<td>
					<input type="text" name="ToneIdEnd11" size="8" maxlength="8" value="" onchange="rfi_update_freq()">
				</td>
				<td>
					<input type="text" name="FreqEnd11" size="16" maxlength="16" value="" disabled>
				</td>
			</tr>
			<tr>
				<th align=center>12</th>
				<td>
					<input type="text" name="ToneId12" size="8" maxlength="8" value="" onchange="rfi_update_freq()">
				</td>
				<td>
					<input type="text" name="Freq12" size="16" maxlength="16" value="" disabled>
				</td>
				<td>
					<input type="text" name="ToneIdEnd12" size="8" maxlength="8" value="" onchange="rfi_update_freq()">
				</td>
				<td>
					<input type="text" name="FreqEnd12" size="16" maxlength="16" value="" disabled>
				</td>
			</tr>
			<tr>
				<th align=center>13</th>
				<td>
					<input type="text" name="ToneId13" size="8" maxlength="8" value="" onchange="rfi_update_freq()">
				</td>
				<td>
					<input type="text" name="Freq13" size="16" maxlength="16" value="" disabled>
				</td>
				<td>
					<input type="text" name="ToneIdEnd13" size="8" maxlength="8" value="" onchange="rfi_update_freq()">
				</td>
				<td>
					<input type="text" name="FreqEnd13" size="16" maxlength="16" value="" disabled>
				</td>
			</tr>
			<tr>
				<th align=center>14</th>
				<td>
					<input type="text" name="ToneId14" size="8" maxlength="8" value="" onchange="rfi_update_freq()">
				</td>
				<td>
					<input type="text" name="Freq14" size="16" maxlength="16" value="" disabled>
				</td>
				<td>
					<input type="text" name="ToneIdEnd14" size="8" maxlength="8" value="" onchange="rfi_update_freq()">
				</td>
				<td>
					<input type="text" name="FreqEnd14" size="16" maxlength="16" value="" disabled>
				</td>
			</tr>
			<tr>
				<th align=center>15</th>
				<td>
					<input type="text" name="ToneId15" size="8" maxlength="8" value="" onchange="rfi_update_freq()">
				</td>
				<td>
					<input type="text" name="Freq15" size="16" maxlength="16" value="" disabled>
				</td>
				<td>
					<input type="text" name="ToneIdEnd15" size="8" maxlength="8" value="" onchange="rfi_update_freq()">
				</td>
				<td>
					<input type="text" name="FreqEnd15" size="16" maxlength="16" value="" disabled>
				</td>
			</tr>
			<tr>
				<th align=center>16</th>
				<td>
					<input type="text" name="ToneId16" size="8" maxlength="8" value="" onchange="rfi_update_freq()">
				</td>
				<td>
					<input type="text" name="Freq16" size="16" maxlength="16" value="" disabled>
				</td>
				<td>
					<input type="text" name="ToneIdEnd16" size="8" maxlength="8" value="" onchange="rfi_update_freq()">
				</td>
				<td>
					<input type="text" name="FreqEnd16" size="16" maxlength="16" value="" disabled>
				</td>
			</tr>
		</table>
	</div>
</div>

<div class="btn_ctl">
	<input class="link_bg" type=submit value="Apply Changes" name="RfiSetup" onClick="return rfi_saveChanges(this)">
	&nbsp;&nbsp;&nbsp;
	<input class="link_bg" type=button value="Back" onclick="location.assign('/admin/vtuo-set.asp')">
	<input type=hidden value="/admin/vtuo-set-rfi.asp" name="submit-url">
	<input type="hidden" name="postSecurityFlag" value="">
</div>
<SCRIPT>
rfi_init();
</SCRIPT>
</form>
<br>
<br>
</body>
</html>
