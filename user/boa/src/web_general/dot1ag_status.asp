<%SendWebHeadStr(); %>
<meta http-equiv="refresh" content="10" > 
<title><% multilang(LANG_CFM_802_1AG_STATUS); %></title>

<script>
<% dot1ag_status_init() %>

function show_table()
{
	var table = document.getElementById("mep_tbl");

	for(var i = 0 ; i < meps.length ; i++)
	{
		var cell;
		var row = table.insertRow(-1);

		for(var j=0 ; j < 7 ; j++)
		{
			cell = row.insertCell(j);
			cell.setAttribute("align", "center");
			cell.setAttribute("bgColor", "#C0C0C0");

			var tmp = "<font size = 2>";

			switch(j)
			{
			case 0:
				tmp += meps[i].interface;
				break;
			case 1:
				tmp += meps[i].status;
				break;
			case 2:
				tmp += meps[i].md_name;
				break;
			case 3:
				tmp += meps[i].ma_name;
				break;
			case 4:
				tmp += meps[i].mep_id;
				break;
			case 5:
				tmp += meps[i].mac;
				break;
			}
			cell.innerHTML = tmp;
		}
	}
}
</script>

</head>


<body onLoad="show_table();">
<div class="intro_main ">
	<p class="intro_title"><% multilang(LANG_CFM_802_1AG_STATUS); %></p>
</div>

<font size=2><b><% multilang(LANG_REMOTE_MEP); %>:</b></font>
<div class="data_common data_common_notitle">
	<table id="mep_tbl">
		<tr>
			<th align=center><% multilang(LANG_INTERFACE); %></th>
			<th align=center><% multilang(LANG_STATUS); %></th>
			<th align=center><% multilang(LANG_MD_NAME); %></th>
			<th align=center><% multilang(LANG_MA_NAME); %></th>
			<th align=center><% multilang(LANG_REMOTE_MEP_ID); %></th>
			<th align=center><% multilang(LANG_SRC_MAC_ADDRESS); %></th>
		</tr>
	</table>
</div>
<br><br>
</body>

</html>
<SCRIPT>

