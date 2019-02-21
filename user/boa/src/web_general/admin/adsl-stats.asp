<% SendWebHeadStr();%>
<META HTTP-EQUIV=Refresh CONTENT="10; URL=adsl-stats.asp">
<title><% checkWrite("adsl_title"); %></title>
</head>

<body>
<div class="intro_main ">
	<p class="intro_title">ADSL Statisitcs</p>
</div>

<form action=/boaform/formStatAdsl method=POST name=sts_adsl>


	<div class="data_common data_common_notitle">
		<table>
			<tr>
				<th width="40%">Mode</th>
				<td ><% getInfo("adsl-drv-mode"); %></td>
			</tr>
			<% checkWrite("adsl_tpstc"); %>
			<tr>
				<th>Latency</th>
				<td bgcolor=#f0f0f0><% getInfo("adsl-drv-latency"); %></td>
			</tr>	
			<% checkWrite("adsl_trellis"); %>
			<tr>
				<th>Status</th>
				<td><% getInfo("adsl-drv-state"); %></td>
			</tr>
			<tr>
				<th>Power Level</th>
				<td><% getInfo("adsl-drv-pwlevel"); %></td>
			</tr>
			<tr>
				<th>Uptime</th>
				<td><% DSLuptime(); %></td>
			</tr>
			<tr <% checkWrite("vdsl-cap"); %>>
				<th>G.Vector</th>
				<td><% getInfo("adsl-drv-vector-mode"); %></td>
			</tr>
		</table>
	</div>
	<div class="data_common data_common_notitle">
		<div class="data_common data_vertical">
			<table>
				<tr>
					<th width="40%"></th>
					<th>Downstream</th>
					<th>Upstream</th>
				</tr>
				<% checkWrite("adsl_trellis_dsus"); %>	
				<tr>
					<th>SNR Margin (dB)</th>
					<td><% getInfo("adsl-drv-snr-ds"); %></td>
					<td><% getInfo("adsl-drv-snr-us"); %></td>
				</tr>
				<tr>
					<th>Attenuation (dB)</th>
					<td><% getInfo("adsl-drv-lpatt-ds"); %></td>
					<td><% getInfo("adsl-drv-lpatt-us"); %></td>
				</tr>
				<tr>
					<th>Output Power (dBm)</th>
					<td><% getInfo("adsl-drv-power-ds"); %></td>
					<td><% getInfo("adsl-drv-power-us"); %></td>
				</tr>
				<tr>
					<th>Attainable Rate (Kbps)</th>
					<td><% getInfo("adsl-drv-attrate-ds"); %></td>
					<td><% getInfo("adsl-drv-attrate-us"); %></td>
				</tr>
				<% checkWrite("adsl_ginp_dsus"); %>
				<tr>
					<th>Rate (Kbps)</th>
					<td><% getInfo("adsl-drv-rate-ds"); %></td>
					<td><% getInfo("adsl-drv-rate-us"); %></td>
				</tr>
				<% checkWrite("adsl_k_dsus"); %>
				<tr>
					<th>R (number of check bytes in RS code word)</th>
					<td><% getInfo("adsl-drv-pms-r-ds"); %></td>
					<td><% getInfo("adsl-drv-pms-r-us"); %></td>
				</tr>
				<% checkWrite("adsl_n_dsus"); %>
				<% checkWrite("adsl_l_dsus"); %>
				<tr>
					<th>S (RS code word size in DMT frame)</th>
					<td><% getInfo("adsl-drv-pms-s-ds"); %></td>
					<td><% getInfo("adsl-drv-pms-s-us"); %></td>
				</tr>
				<tr>
					<th>D (interleaver depth)</th>
					<td><% getInfo("adsl-drv-pms-d-ds"); %></td>
					<td><% getInfo("adsl-drv-pms-d-us"); %></td>
				</tr>
				<tr>
					<th>Delay (msec)</th>
					<td><% getInfo("adsl-drv-pms-delay-ds"); %></td>
					<td><% getInfo("adsl-drv-pms-delay-us"); %></td>
				</tr>
				<% checkWrite("adsl_inp_dsus"); %>
				<tr>
					<th><% checkWrite("adsl_fec_name"); %></th>
					<td><% getInfo("adsl-drv-fec-ds"); %></td>
					<td><% getInfo("adsl-drv-fec-us"); %></td>
				</tr>
				<% checkWrite("adsl_ohframe_dsus"); %>
				<tr>
					<th><% checkWrite("adsl_crc_name"); %></th>
					<td><% getInfo("adsl-drv-crc-ds"); %></td>
					<td><% getInfo("adsl-drv-crc-us"); %></td>
				</tr>
				<tr>
					<th>Total ES</th>
					<td><% getInfo("adsl-drv-es-ds"); %></td>
					<td><% getInfo("adsl-drv-es-us"); %></td>
				</tr>
				<tr>
					<th>Total SES</th>
					<td><% getInfo("adsl-drv-ses-ds"); %></td>
					<td><% getInfo("adsl-drv-ses-us"); %></td>
				</tr>
				<tr>
					<th>Total UAS</th>
					<td><% getInfo("adsl-drv-uas-ds"); %></td>
					<td><% getInfo("adsl-drv-uas-us"); %></td>
				</tr>
				<tr>
					<th>Total LOSS</th>
					<td><% getInfo("adsl-drv-los-ds"); %></td>
					<td><% getInfo("adsl-drv-los-us"); %></td>
				</tr>
				<% checkWrite("adsl_llr_dsus"); %>	
			</table>
		</div>
	</div>
	<div class="data_common data_common_notitle">
		<table>
			<tr>
				<th width="40%">Full Init</th>
				<td><% getInfo("adsl-drv-lnk-fi"); %></td>
			</tr>
			<tr>
				<th>Failed Full Init</th>
				<td><% getInfo("adsl-drv-lnk-lfi"); %></td>
			</tr>
			<% checkWrite("adsl_llr"); %>
			<% checkWrite("adsl_txrx_frame"); %>
			<tr>
				<th>Synchronized time(Second)</th>
				<td><% getInfo("adsl-drv-synchronized-time"); %></td>
			</tr>
			<tr>
				<th>Synchronized number</th>
				<td><% getInfo("adsl-drv-synchronized-number"); %></td>
			</tr>
		</table>
	</div>
</form>
<br><br>
</body>
</html>
