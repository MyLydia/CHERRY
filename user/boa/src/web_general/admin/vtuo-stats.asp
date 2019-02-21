<%SendWebHeadStr(); %>
<!--<META HTTP-EQUIV=Refresh CONTENT="10; URL=vtuo-stats.asp">-->
<title>VTU-O DSL Statistics</title>
<SCRIPT>
var reload_page;
var btn_reload_stat=0;

function vtuo_stat_reload_cb()
{
	location.assign('/admin/vtuo-stats.asp'); 
}

function vtuo_stat_reload_start()
{
	btn_reload_stat=1;
	document.set_vtuo_st.btn_reload.value="Stop Auto-Refresh"
	reload_page=setTimeout("vtuo_stat_reload_cb()",10000);
}

function vtuo_stat_reload()
{
	if(btn_reload_stat)
	{
		btn_reload_stat=0;
		document.set_vtuo_st.btn_reload.value="Start Auto-Refresh"
		clearTimeout(reload_page);
	}else{
		vtuo_stat_reload_cb();
	}
}

</SCRIPT>
</head>

<body onload="vtuo_stat_reload_start()">
<div class="intro_main ">
	<p class="intro_title">VTU-O DSL Statistics</p>
</div>

<form action=/boaform/formSetVTUO method=POST name=set_vtuo_st>
<div class="btn_ctl">
	<input class="link_bg" type=button name="btn_reload" value="" onclick="vtuo_stat_reload();">
</div>

<div class="column">
	<div class="column_title">
		<div class="column_title_left"></div>
			<p>1. Port Info</p>
		<div class="column_title_right"></div>
	</div>
	<div class="data_common">
		<table>
		<!--	<tr>
				<th width=30%>Name</th>
				<td></td>
			</tr>
		-->
			<tr>
				<th width=30%>DSL Standard:</th>
				<td><% getInfo("adsl-drv-pmd-mode"); %></td>
			</tr>
			<tr>
				<th>Band Plan:</th>
				<td><% getInfo("adsl-drv-link-type"); %></td>
			</tr>	
			<tr>
				<th>DSL Link State:</th>
				<td><% getInfo("adsl-drv-state"); %></td>
			</tr>
			<tr>
				<th>Up Time:</th>
				<td><% DSLuptime(); %></td>
			</tr>
		<!--
			<tr>
				<th>Actual Template</th>
				<td></td>
			</tr>
			<tr>
				<th>Init Result</th>
				<td></td>
			</tr>
		-->
			<tr>
				<th>DS Mask:</th>
				<td><% getInfo("adsl-drv-limit-mask"); %></td>
			</tr>
			<tr>
				<th>US0 Mask:</th>
				<td><% getInfo("adsl-drv-us0-mask"); %></td>
			</tr>
			<tr>
				<th>Electrical Length (dB):</th>
				<td><% getInfo("adsl-drv-upbokle-us"); %></td>
			</tr>
			<!--
			<tr>
				<th>Cyclic Extension</th>
				<td><% getInfo("adsl-drv-actualce"); %></td>
			</tr>
			-->
		</table>
	</div>
</div>

<div class="column">
	<div class="column_title">
		<div class="column_title_left"></div>
			<p>2. VDSL Status</p>
		<div class="column_title_right"></div>
	</div>
	<div class="data_common data_vertical">
		<table>
			<tr>
				<th width=30%></th>
				<th>Downstream</th>
				<th>Upstream</th>
			</tr>
			<tr>
				<th>Attainable net data rate (Kbps)</th>
				<td><% getInfo("adsl-drv-attrate-ds"); %></td>
				<td><% getInfo("adsl-drv-attrate-us"); %></td>
			</tr>
			<tr>
				<th>SNR Margin (dB)</th>
				<td><% getInfo("adsl-drv-snr-ds"); %></td>
				<td><% getInfo("adsl-drv-snr-us"); %></td>
			</tr>
			<tr>
				<th>Signal Attenuation (dB)</th>
				<td><% getInfo("adsl-drv-signal-atn-ds"); %></td>
				<td><% getInfo("adsl-drv-signal-atn-us"); %></td>
			</tr>
			<tr>
				<th>Line Attenuation (dB)</th>
				<td><% getInfo("adsl-drv-line-atn-ds"); %></td>
				<td><% getInfo("adsl-drv-line-atn-us"); %></td>
			</tr>
			<tr>
				<th>Transmit Power (dBm)</th>
				<td><% getInfo("adsl-drv-power-ds"); %></td>
				<td><% getInfo("adsl-drv-power-us"); %></td>
			</tr>
			<tr>
				<th>Trellis</th>
				<td><% getInfo("adsl-drv-trellis-ds"); %></td>
				<td><% getInfo("adsl-drv-trellis-us"); %></td>
			</tr>
		<!--
			<tr>
				<th>SNR Mode</th>
				<td></td>
				<td></td>
			</tr>
			<tr>
				<th>Last State</th>
				<td></td>
				<td></td>
			</tr>
			<tr>
				<th>Current State</th>
				<td></td>
				<td></td>
			</tr>
		-->
			<tr>
				<th>Actual net data rate (Kbps)</th>
				<td><% getInfo("adsl-drv-rate-ds"); %></td>
				<td><% getInfo("adsl-drv-rate-us"); %></td>
			</tr>
			<!--
			<tr>
				<th>Prev net data rate (Kbps)</th>
				<td><% getInfo("adsl-drv-lnk-llds"); %></td>
				<td><% getInfo("adsl-drv-lnk-llus"); %></td>
			</tr>
			-->
			<tr>
				<th>Actual Delay (msec)</th>
				<td><% getInfo("adsl-drv-pms-delay-ds"); %></td>
				<td><% getInfo("adsl-drv-pms-delay-us"); %></td>
			</tr>
			<tr>
				<th>Actual INP (symbol)</th>
				<td><% getInfo("adsl-drv-inp-ds"); %></td>
				<td><% getInfo("adsl-drv-inp-us"); %></td>
			</tr>
			<tr>
				<th>Receive Power (dBm)</th>
				<td><% getInfo("adsl-drv-rx-power-ds"); %></td>
				<td><% getInfo("adsl-drv-rx-power-us"); %></td>
			</tr>
		<!--
			<tr>
				<th>INP Report</th>
				<td></td>
				<td></td>
			</tr>
		-->
			<tr>
				<th>Np</th>
				<td><% getInfo("adsl-drv-n-ds"); %></td>
				<td><% getInfo("adsl-drv-n-us"); %></td>
			</tr>
			<tr>
				<th>Rp</th>
				<td><% getInfo("adsl-drv-pms-r-ds"); %></td>
				<td><% getInfo("adsl-drv-pms-r-us"); %></td>
			</tr>
			<tr>
				<th>Lp</th>
				<td><% getInfo("adsl-drv-l-ds"); %></td>
				<td><% getInfo("adsl-drv-l-us"); %></td>
			</tr>
			<tr>
				<th>Dp</th>
				<td><% getInfo("adsl-drv-pms-d-ds"); %></td>
				<td><% getInfo("adsl-drv-pms-d-us"); %></td>
			</tr>
			<tr>
				<th>Ip</th>
				<td><% getInfo("adsl-drv-pmspara-i-ds"); %></td>
				<td><% getInfo("adsl-drv-pmspara-i-us"); %></td>
			</tr>
			<!--
			<tr>
				<th>Actual Latency Path</th>
				<td><% getInfo("adsl-drv-data-lpid-ds"); %></td>
				<td><% getInfo("adsl-drv-data-lpid-us"); %></td>
			</tr>
			<tr>
				<th>PTM Status</th>
				<td><% getInfo("adsl-drv-ptm-status"); %></td>
				<td><% getInfo("adsl-drv-ptm-status"); %></td>
			</tr>
			<tr>
				<th>Actual RA Mode</th>
				<td><% getInfo("adsl-drv-ra-mode-ds"); %></td>
				<td><% getInfo("adsl-drv-ra-mode-us"); %></td>
			</tr>
			-->
			<tr>
				<th>G.INP Mode</th>
				<td><% getInfo("adsl-drv-ginp-ds"); %></td>
				<td><% getInfo("adsl-drv-ginp-us"); %></td>
			</tr>
			<tr>
				<th>G.INP OH Rate (Kbps)</th>
				<td><% getInfo("adsl-drv-retx-ohrate-ds"); %></td>
				<td><% getInfo("adsl-drv-retx-ohrate-us"); %></td>
			</tr>
			<tr>
				<th>G.INP Framing Type</th>
				<td><% getInfo("adsl-drv-retx-fram-type-ds"); %></td>
				<td><% getInfo("adsl-drv-retx-fram-type-us"); %></td>
			</tr>
			<tr>
				<th>G.INP INP_act_REIN (symbol)</th>
				<td><% getInfo("adsl-drv-retx-actinp-rein-ds"); %></td>
				<td><% getInfo("adsl-drv-retx-actinp-rein-us"); %></td>
			</tr>
			<!--
			<tr>
				<th>RS CW per DTU</th>
				<td><% getInfo("adsl-drv-retx-h-ds"); %></td>
				<td><% getInfo("adsl-drv-retx-h-us"); %></td>
			</tr>
			-->
		</table>
	</div>
</div>

<div class="column">
	<div class="column_title">
		<div class="column_title_left"></div>
			<p>3. VDSL Band</p>
		<div class="column_title_right"></div>
	</div>
	<div class="data_common data_vertical">
		<table border=0 width=500 cellspacing=4 cellpadding=0>
			<tr>
				<th></th>
				<th>US0</th><th>US1</th><th>US2</th><th>US3</th><th>US4</th>
				<th>DS1</th><th>DS2</th><th>DS3</th><th>DS4</th>
			</tr>
			<% vtuo_checkWrite("stat-band"); %>
		</table>
	</div>
</div>


<div class="column">
	<div class="column_title">
		<div class="column_title_left"></div>
			<p>4. DSL PM Counters</p>
		<div class="column_title_right"></div>
	</div>
	<div class="data_common">
		<table>
			<% vtuo_checkWrite("stat-perform"); %>	
		</table>
	</div>
</div>

<div class="column">
	<div class="column_title">
		<div class="column_title_left"></div>
			<p>5. VDSL Performance History</p>
		<div class="column_title_right"></div>
	</div>
	<div class="data_common">
		<table>
			<table>
				<tr>
					<td>* <a href="/boaform/formSetVTUO?StatusPage=15min" target="_blank">15 Min Interval</a></td>
				</tr>
				<tr>
					<td>* <a href="/boaform/formSetVTUO?StatusPage=oneday" target="_blank">One Day Interval</a></td>
				</tr>
			</table>	
		</table>
	</div>
</div>

<div class="column">
	<div class="column_title">
		<div class="column_title_left"></div>
			<p>6. VDSL sub-carrier status</p>
		<div class="column_title_right"></div>
	</div>
	<div class="data_common data_vertical">
		<table>
			<tr>
				<th></th>
				<th>Downstream</th>
				<th>Upstream</th>
			</tr>
			<!--
			<tr>
				<th>HLOG</th>
				<td><a href="/boaform/formSetVTUO?StatusPage=hlog_ds" target="_blank">Show</a></td>
				<td><a href="/boaform/formSetVTUO?StatusPage=hlog_us" target="_blank">Show</a></td>
			</tr>
			<tr>
				<th>QLN</th>
				<td><a href="/boaform/formSetVTUO?StatusPage=qln_ds" target="_blank">Show</a></td>
				<td><a href="/boaform/formSetVTUO?StatusPage=qln_us" target="_blank">Show</a></td>
			</tr>
			<tr>
				<th>SNR</th>
				<td><a href="/boaform/formSetVTUO?StatusPage=snr_ds" target="_blank">Show</a></td>
				<td><a href="/boaform/formSetVTUO?StatusPage=snr_us" target="_blank">Show</a></td>
			</tr>
			-->
			<tr>
				<th>Bi Table</th>
				<td><a href="/boaform/formSetVTUO?StatusPage=bit_ds" target="_blank">Show</a></td>
				<td><a href="/boaform/formSetVTUO?StatusPage=bit_us" target="_blank">Show</a></td>
			</tr>
			<tr>
				<th>Gi Table</th>
				<td><a href="/boaform/formSetVTUO?StatusPage=gain_ds" target="_blank">Show</a></td>
				<td><a href="/boaform/formSetVTUO?StatusPage=gain_us" target="_blank">Show</a></td>
			</tr>
		</table>
	</div>
</div>

<!--
<h4>7. MEDLEY PSD</h4>
<table border=0 width=500 cellspacing=4 cellpadding=0>
	<tr>
		<th colspan=3>Downstream</th>
		<th colspan=3>Upstream</th>
	</tr>
	<tr>
		<th>Break<br>Point</th>
		<th>Tone Index</th>
		<th>PSD Level<br>(dBm/Hz)</th>
		<th>Break<br>Point</th>
		<th>Tone Index</th>
		<th>PSD Level<br>(dBm/Hz)</th>
	</tr>

	<% vtuo_checkWrite("stat-medley-psd"); %>

</table>
-->

</form>
<br><br>
</body>

</html>
