<%SendWebHeadStr(); %>
<meta http-equiv=Refresh CONTENT="10">
<title>PON Statistics</title>
</head>

<body>
<div class="intro_main ">
	<p class="intro_title"><% multilang(LANG_PON_STATISTICS); %></p>
</div>

<div class="data_common data_common_notitle">
	<table>
		<tr>
			<th><% multilang(LANG_BYTES_SENT); %>:</th>
			<td><% ponGetStatus("bytes-sent"); %></td>
		</tr>
		<tr>
			<th><% multilang(LANG_BYTES_RECEIVED); %>:</th>
			<td><% ponGetStatus("bytes-received"); %></td>
		</tr>	
		<tr>
			<th><% multilang(LANG_PACKETS_SENT); %>:</th>
			<td><% ponGetStatus("packets-sent"); %></td>
		</tr>
		<tr>
			<th><% multilang(LANG_PACKETS_RECEIVED); %>:</th>
			<td><% ponGetStatus("packets-received"); %></td>
		</tr>	
		<tr>
			<th><% multilang(LANG_UNICAST_PACKETS_SENT); %>:</th>
			<td><% ponGetStatus("unicast-packets-sent"); %></td>
		</tr>
		<tr>
			<th><% multilang(LANG_UNICAST_PACKETS_RECEIVED); %>:</th>
			<td><% ponGetStatus("unicast-packets-received"); %></td>
		</tr>	
		<tr>
			<th><% multilang(LANG_MULTICAST_PACKETS_SENT); %>:</th>
			<td><% ponGetStatus("multicast-packets-sent"); %></td>
		</tr>
		<tr>
			<th><% multilang(LANG_MULTICAST_PACKETS_RECEIVED); %>:</th>
			<td><% ponGetStatus("multicast-packets-received"); %></td>
		</tr>	
		<tr>
			<th><% multilang(LANG_BROADCAST_PACKETS_SENT); %>:</th>
			<td><% ponGetStatus("broadcast-packets-sent"); %></td>
		</tr>
		<tr>
			<th><% multilang(LANG_BROADCAST_PACKETS_RECEIVED); %>:</th>
			<td><% ponGetStatus("broadcast-packets-received"); %></td>
		</tr>	
		<tr>
			<th><% multilang(LANG_FEC_ERRORS); %>:</th>
			<td><% ponGetStatus("fec-errors"); %></td>
		</tr>
		<tr>
			<th><% multilang(LANG_HEC_ERRORS); %>:</th>
			<td><% ponGetStatus("hec-errors"); %></td>
		</tr>	
		<tr>
			<th><% multilang(LANG_PACKETS_DROPPED); %>:</th>
			<td><% ponGetStatus("packets-dropped"); %></td>
		</tr>
		<tr>
			<th><% multilang(LANG_PAUSE_PACKETS_SENT); %>:</th>
			<td><% ponGetStatus("pause-packets-sent"); %></td>
		</tr>	
		<tr>
			<th><% multilang(LANG_PAUSE_PACKETS_RECEIVED); %>:</th>
			<td><% ponGetStatus("pause-packets-received"); %></td>
		</tr>
	</table>
</div>
</body>
</html>
