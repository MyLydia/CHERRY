<html>
<! Copyright (c) Realtek Semiconductor Corp., 2003. All Rights Reserved. ->
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<title><% multilang(LANG_VLAN_MAPPING); %> <% multilang(LANG_CONFIGURATION); %></title>
<script type="text/javascript" src="share.js"></script>
<script>
var vlan_mapping_tabel = <% checkWrite("vlan_mapping_tabel"); %>;

function saveClick()
{
	with (document.forms[0])
	{
		var i = 0, j = 0;
		for(i = 0; i < vlan_mapping_tabel.length; i++)
		{
			if (vlan_mapping_tabel[i][0] == intf_sel.value) {
				var pair_num = vlan_mapping_tabel[i].length - 1;
				for (j = 0; j < pair_num; j++) {
					var lan_vid_input = "Frm_VLAN" + j + "a";
					var wan_vid_input = "Frm_VLAN" + j + "b";

					if (document.getElementById(lan_vid_input).value == "" || document.getElementById(wan_vid_input).value == "") {
						alert("<% multilang(LANG_VID_CANNOT_BE_EMPTY); %>");
						return false;
					}

					if ((document.getElementById(lan_vid_input).value < 0 || document.getElementById(lan_vid_input).value >= 4096) || 
						(document.getElementById(wan_vid_input).value < 0 || document.getElementById(wan_vid_input).value >= 4096))
					{
						alert("<% multilang(LANG_INCORRECT_VLAN_ID_SHOULE_BE_1_4095); %>");
						return false;
					}
				}
				break;
			}
		}
	}
	return true;
}

function updateState()
{
	with (document.forms[0])
	{
		var i = 0, j = 0;
		for(i = 0; i < vlan_mapping_tabel.length; i++)
		{
			if (vlan_mapping_tabel[i][0] == intf_sel.value) {
				var pair_num = vlan_mapping_tabel[i].length - 1;
				for (j = 0; j < pair_num; j++) {
					var lan_vid_input = "Frm_VLAN" + j + "a";
					var wan_vid_input = "Frm_VLAN" + j + "b";

					document.getElementById(lan_vid_input).value = vlan_mapping_tabel[i][(j + 1)][0].toString();
					document.getElementById(wan_vid_input).value = vlan_mapping_tabel[i][(j + 1)][1].toString();
				}
				break;
			}
		}
	}
}
</script>
</head>

<body>
<blockquote>
<h2><font color="#0000FF"><% multilang(LANG_VLAN_MAPPING); %> <% multilang(LANG_CONFIGURATION); %></font></h2>

<table border=0 width="500" cellspacing=0 cellpadding=0>
	<tr>
		<td>
			<font size=2>
				<% multilang(LANG_VLAN_MAPPING_DESC); %>
			</font>
		</td>
	</tr>
	<tr>
		<td>
			<hr size=1 noshade align=top>
		</td>
	</tr>
</table>

<form action=/boaform/admin/formVLANMapping method=POST name="formVLANMapping">
	<table border=0 width="500" cellspacing=0 cellpadding=0>
		<tr>
			<td>
				<font size=2><b><% multilang(LANG_INTERFACE); %>:  </b></font>
				<select name="intf_sel" id="intf_sel" onchange="updateState()" >
					<% itfSelList(); %>
			</td>
		</tr>
		<table border=0 width="500" cellspacing=0 cellpadding=0>
			<tr>
				<td><font size=2><b>LAN VLAN ID</b></td>
				<td><font size=2><b>WAN VLAN ID</b></td>
			</tr>
			<% mappingInputList(); %>
		</table>

	</table>
	<br>
	<input type="submit" value="<% multilang(LANG_APPLY_CHANGES); %>" name="save" onClick="return saveClick()">
	<input type="hidden" value="/admin/vlan_mapping.asp" name="submit-url">
	<script>updateState();</script>
</form>
</blockquote>
</body>
</html>
