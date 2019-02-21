<html>
<! Copyright (c) Realtek Semiconductor Corp., 2003. All Rights Reserved. ->
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<title><% checkWrite("adsl_set_title"); %></title>
<SCRIPT language="javascript" src="/common.js"></SCRIPT>
<SCRIPT>

function dhcpTblClick(url) {
	openWindow(url, 'DHCPTbl' );
}

function adsltoneClick(url)
{
	var wide=600;
	var high=400;
	if (document.all)
		var xMax = screen.width, yMax = screen.height;
	else if (document.layers)
		var xMax = window.outerWidth, yMax = window.outerHeight;
	else
	   var xMax = 640, yMax=480;
	var xOffset = (xMax - wide)/2;
	var yOffset = (yMax - high)/3;

	var settings = 'width='+wide+',height='+high+',screenX='+xOffset+',screenY='+yOffset+',top='+yOffset+',left='+xOffset+', resizable=yes, toolbar=no,location=no,directories=no,status=no,menubar=no,scrollbars=yes';

	window.open( url, 'ADSLTONETbl', settings );
}

function saveChanges()
{               
	if (document.set_adsl.glite.checked == false
	   && document.set_adsl.gdmt.checked == false
	   && document.set_adsl.t1413.checked == false
	   && document.set_adsl.adsl2.checked == false
<% initPage("vdsl2_check"); %>
<% initPage("gfast_check"); %>
	   && document.set_adsl.adsl2p.checked == false) {
		alert("ADSL modulation cannot be empty.");
		return false;
	}

<% initPage("vdsl2_check_profile"); %>
<% initPage("gfast_check_profile"); %>

	document.set_adsl.save.isclick = 1;
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	
	return true;
}

<% initPage("vdsl2_updatefn"); %>
<% initPage("gfast_updatefn"); %>

</SCRIPT>
</head>

<body>
<blockquote>
<h2><font color="#0000FF"><% checkWrite("adsl_set_title"); %></font></h2>

<form action=/boaform/formSetAdsl method=POST name=set_adsl>
<table border=0 width=500 cellspacing=4 cellpadding=0>
	<tr><td><font size=2>
	  <% multilang(LANG_THIS_PAGE_IS_USED_TO_CONFIGURE_THE_PARAMETERS_FOR_THE_BANDS_OF_YOUR_DEVICE); %>
	</font></td></tr>
	<tr><td><hr size=1 noshade align=top></td></tr>
</table>

<table border=0 width=500 cellspacing=4 cellpadding=0>
<tr>
	<th align=left width=30%><font size=2><% checkWrite("xdsl_type"); %> <% multilang(LANG_MODULATION); %>:</th>
	<td width=70%></td>
</tr>
<tr <% checkWrite("anxb-cap", "0"); %>>
	<th></th>
	<td><font size=2><input type=checkbox name=glite value=1>G.Lite</td>
</tr>
<tr>
	<th></th>
	<td><font size=2><input type=checkbox name=gdmt value=1>G.Dmt</td>
</tr>
<tr>
	<th></th>
	<td id="t1413_id"><font size=2><input type=checkbox name=t1413 value=1>T1.413</td>
</tr>
<tr>
	<th></th>
	<td><font size=2><input type=checkbox name=adsl2 value=1>ADSL2</td>
</tr>
<tr>
	<th></th>
	<td><font size=2><input type=checkbox name=adsl2p value=1>ADSL2+</td>
</tr>
<% initPage("vdsl2_opt"); %>
<% initPage("gfast_opt"); %>
<tr <% checkWrite("anxb-cap", "1"); %>>
	<th align=left width=30%><font size=2>AnnexJ <% multilang(LANG_OPTION); %>:</th>
	<td width=70%><font size=2>(<% multilang(LANG_NOTE_ONLY_ADSL_2_2_SUPPORT_ANNEXJ); %>)</td>
</tr>
<tr <% checkWrite("anxb-cap", "1"); %>>
	<th></th>
	<td><font size=2><input type=checkbox name=anxj value=1><% multilang(LANG_ENABLED); %></td>
</tr>
<tr <% checkWrite("anxb-cap", "0"); %>>
	<th align=left width=30%><font size=2>AnnexL <% multilang(LANG_OPTION); %>:</th>
	<td width=70%><font size=2>(<% multilang(LANG_NOTE_ONLY_ADSL_2_S_UPPORTS_ANNEXL); %>)</td>
</tr>
<tr <% checkWrite("anxb-cap", "0"); %>>
	<th></th>
	<td><font size=2><input type=checkbox name=anxl value=1><% multilang(LANG_ENABLED); %></td>
</tr>
<tr <% checkWrite("anxb-cap", "0"); %>>
	<th align=left width=30%><font size=2>AnnexM <% multilang(LANG_OPTION); %>:</th>
	<td width=70%><font size=2>(<% multilang(LANG_NOTE_ONLY_ADSL_2_2_SUPPORT_ANNEXM); %>)</td>
</tr>
<tr <% checkWrite("anxb-cap", "0"); %>>
	<th></th>
	<td><font size=2><input type=checkbox name=anxm value=1><% multilang(LANG_ENABLED); %></td>
</tr>
<tr <% checkWrite("ginp-cap"); %>>
	<th align=left width=30%><font size=2>G.INP <% multilang(LANG_OPTION); %>:</font></th>
	<td></td>
</tr>
<tr <% checkWrite("ginp-cap"); %>>
	<th></th>
	<td><font size=2><input type=checkbox name=ginp value=1><% multilang(LANG_ENABLED); %></font></td>
</tr>
<tr  <% checkWrite("vdsl-cap"); %>>
	<th align=left width=30%><font size=2>G.Vector <% multilang(LANG_OPTION); %>:</font></th>
	<td></td>
</tr>
<tr  <% checkWrite("vdsl-cap"); %>>
	<th></th>
	<td><font size=2><input type=checkbox name=gvec value=1><% multilang(LANG_ENABLED); %></font></td>
</tr>
<% initPage("vdsl2_profile"); %>
<% initPage("gfast_profile"); %>
<tr>
	<th align=left><font size=2>DSL <% multilang(LANG_CAPABILITY); %>:</th>
	<td></td>
</tr>
<tr>
	<th></th>
	<td><font size=2><input type=checkbox name=bswap value=1><% multilang(LANG_ENABLED); %> Bitswap</td>
</tr>
<tr>
	<th></th>
	<td><font size=2><input type=checkbox name=sra value=1><% multilang(LANG_ENABLED); %> SRA</td>
</tr>

<% initPage("adsl_tone_mask"); %>
<% initPage("adsl_psd_mask"); %>
<% initPage("psd_msm_mode"); %>

</table>
  <br>
	<input type=submit value="<% multilang(LANG_APPLY_CHANGES); %>" name="save" onClick="return saveChanges()">
	<input type=hidden value="/admin/adsl-set.asp" name="submit-url">
	<input type="hidden" name="postSecurityFlag" value="">
<script>
	<% initPage("setdsl"); %>
</script>
</form>
</blockquote>
</body>

</html>
