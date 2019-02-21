<html>
<! Copyright (c) Realtek Semiconductor Corp., 2003. All Rights Reserved. ->
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<title><% multilang(LANG_GPON_TYPE); %></title>
<script type="text/javascript" src="share.js">
</script>
<script>

<% fmgpon_checkWrite("fmgpon_type_init"); %>

function update_gui()
{
	if(document.fmgponType.device_type.value == 1) //router
		document.getElementById('div_lan').style.display='none';
	else
		document.getElementById('div_lan').style.display='';
}

function on_init()
{
	with(document.fmgponType)
	{
		device_type.value = dev_type;

		for(var i = 0 ; i < 4 ; i++)
		{
			/* We do not alwasy have 4 LAN ports */
			if (!chkpt[i])
				break;
			chkpt[i].checked = (pmask & (0x1 << i));
		}
	}
	update_gui();
}

function applyclick()
{
	if ( !confirm('<% multilang(LANG_GPON_TYPE_CONFIRM_MSG); %>') )
	{
		return false;
  	}

	with (document.fmgponType)
	{
		var pmap = 0;

		for (var i = 0; i < 4; i++) {
			/* chkpt do not always have 14 elements */
			if (!chkpt[i])
				break;

			if (chkpt[i].checked == true)
				pmap |= (0x1 << i);
		}
		portmask.value = pmap;
	}

	return true;
}
</script>
</head>

<body onLoad="on_init();">
<blockquote>
<h2><font color="#0000FF"><% multilang(LANG_GPON_TYPE); %></font></h2>
<form action=/boaform/admin/fmgponType method=POST name="fmgponType">
<!--table border=0 width="500" cellspacing=4 cellpadding=0>
  <tr><td><font size=2>
    <% multilang(LANG_GPON_TYPE_DESC); %>
  </font></td></tr>
  <tr><td><hr size=1 noshade align=top></td></tr>
</table-->
<table border=0 width="500" cellspacing=4 cellpadding=0>
<tr>
	<td width="30%"><font size=2><b><% multilang(LANG_GPON_TYPE); %>:</b></td>
	<td width="70%"><select name="device_type" onchange="update_gui();">
		<option value = 1>Router</option>
		<option value = 2>Hybrid</option>
	</select></td>
</tr>
</table>
<div id=div_lan>
	<% showPonLanPorts %>
</div>
<br>
      <input type="submit" value="<% multilang(LANG_APPLY_CHANGES); %>" name="apply" onClick="return applyclick()">&nbsp;&nbsp;
      <input type="hidden" name="portmask" value=0>
      <input type="hidden" value="/gpon_type.asp" name="submit-url">
</form>
</blockquote>
</body>
</html>
