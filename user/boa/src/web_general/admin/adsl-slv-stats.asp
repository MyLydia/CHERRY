<%SendWebHeadStr(); %>
<META HTTP-EQUIV=Refresh CONTENT="10; URL=adsl-slv-stats.asp">
<title><% checkWrite("adsl_slv_title"); %></title>
</head>

<body>
<div class="intro_main ">
	<p class="intro_title"><% checkWrite("adsl_slv_title"); %></p>
</div>

<form action=/boaform/formStatAdsl method=POST name=sts_adsl>

<table>
	<tr>
		<th>Mode</th>
		<td><% getInfo("adsl-slv-drv-mode"); %></td>
	</tr>
<% checkWrite("adsl_slv_tpstc"); %>
	<tr>
		<th>Latency</th>
		<td><% getInfo("adsl-slv-drv-latency"); %></td>
	</tr>	
<% checkWrite("adsl_slv_trellis"); %>
	<tr>
		<th>Status</th>
		<td><% getInfo("adsl-slv-drv-state"); %></td>
	</tr>
	<tr>
		<th>Power Level</th>
		<td><% getInfo("adsl-slv-drv-pwlevel"); %></td>
	</tr>
	<tr>
		<th>Uptime</th>
		<td><% DSLSlvuptime(); %></td>
	</tr>
	<tr <% checkWrite("vdsl-cap"); %>>
		<th>G.Vector</th>
		<td><% getInfo("adsl-slv-drv-vector-mode"); %></td>
	</tr>
</table>

<table>
	<tr>
		<th>Downstream</th>
		<th>Upstream</th>
	</tr>
<% checkWrite("adsl_slv_trellis_dsus"); %>	
	<tr>
		<th>SNR Margin (dB)</th>
		<td><% getInfo("adsl-slv-drv-snr-ds"); %></td><td><% getInfo("adsl-slv-drv-snr-us"); %></td>
	</tr>
	<tr>
		<th>Attenuation (dB)</th>
		<td><% getInfo("adsl-slv-drv-lpatt-ds"); %></td><td><% getInfo("adsl-slv-drv-lpatt-us"); %></td>
	</tr>
	<tr>
		<th>Output Power (dBm)</th>
		<td><% getInfo("adsl-slv-drv-power-ds"); %></td><td><% getInfo("adsl-slv-drv-power-us"); %></td>
	</tr>
	<tr>
		<th>Attainable Rate (Kbps)</th>
		<td><% getInfo("adsl-slv-drv-attrate-ds"); %></td><td><% getInfo("adsl-slv-drv-attrate-us"); %></td>
	</tr>
<% checkWrite("adsl_slv_ginp_dsus"); %>
	<tr>
		<th>Rate (Kbps)</th>
		<td><% getInfo("adsl-slv-drv-rate-ds"); %></td><td><% getInfo("adsl-slv-drv-rate-us"); %></td>
	</tr>
<% checkWrite("adsl_slv_k_dsus"); %>
	<tr>
		<th>R (number of check bytes in RS code word)</th>
		<td><% getInfo("adsl-slv-drv-pms-r-ds"); %></td><td><% getInfo("adsl-slv-drv-pms-r-us"); %></td>
	</tr>
<% checkWrite("adsl_slv_n_dsus"); %>
<% checkWrite("adsl_slv_l_dsus"); %>
	<tr>
		<th>S (RS code word size in DMT frame)</th>
		<td><% getInfo("adsl-slv-drv-pms-s-ds"); %></td><td><% getInfo("adsl-slv-drv-pms-s-us"); %></td>
	</tr>
	<tr>
		<th>D (interleaver depth)</th>
		<td><% getInfo("adsl-slv-drv-pms-d-ds"); %></td><td><% getInfo("adsl-slv-drv-pms-d-us"); %></td>
	</tr>
	<tr>
		<th>Delay (msec)</th>
		<td><% getInfo("adsl-slv-drv-pms-delay-ds"); %></td><td><% getInfo("adsl-slv-drv-pms-delay-us"); %></td>
	</tr>
<% checkWrite("adsl_slv_inp_dsus"); %>
	<tr>
		<th><% checkWrite("adsl_fec_name"); %></th>
		<td><% getInfo("adsl-slv-drv-fec-ds"); %></td><td><% getInfo("adsl-slv-drv-fec-us"); %></td>
	</tr>
<% checkWrite("adsl_slv_ohframe_dsus"); %>
	<tr>
		<th><% checkWrite("adsl_crc_name"); %></th>
		<td><% getInfo("adsl-slv-drv-crc-ds"); %></td><td><% getInfo("adsl-slv-drv-crc-us"); %></td>
	</tr>

	<tr>
		<th>Total ES</th>
		<td><% getInfo("adsl-slv-drv-es-ds"); %></td><td><% getInfo("adsl-slv-drv-es-us"); %></td>
	</tr>
	<tr>
		<th>Total SES</th>
		<td><% getInfo("adsl-slv-drv-ses-ds"); %></td><td><% getInfo("adsl-slv-drv-ses-us"); %></td>
	</tr>
	<tr>
		<th>Total UAS</th>
		<td><% getInfo("adsl-slv-drv-uas-ds"); %></td><td><% getInfo("adsl-slv-drv-uas-us"); %></td>
	</tr>
	<tr>
		<th>Total LOSS</th>
		<td><% getInfo("adsl-slv-drv-los-ds"); %></td><td><% getInfo("adsl-slv-drv-los-us"); %></td>
	</tr>
<% checkWrite("adsl_slv_llr_dsus"); %>	

	<tr>
		<th>Full Init</th>
		<td colspan=2><% getInfo("adsl-slv-drv-lnk-fi"); %></td>
	</tr>
	<tr>
		<th>Failed Full Init</th>
		<td colspan=2><% getInfo("adsl-slv-drv-lnk-lfi"); %></td>
	</tr>
<% checkWrite("adsl_slv_llr"); %>
<% checkWrite("adsl_slv_txrx_frame"); %>
	<tr>
		<th>Synchronized time(Second)</th>
		<td colspan=2><% getInfo("adsl-slv-drv-synchronized-time"); %></td>
	</tr>
	<tr>
		<th>Synchronized number</th>
		<td colspan=2><% getInfo("adsl-slv-drv-synchronized-number"); %></td>
	</tr>
</table>
<p>
</form>
<br><br>
</body>

</html>
