<html>
<! Copyright (c) Realtek Semiconductor Corp., 2003. All Rights Reserved. ->
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<title>Html Wizard</title>
<link href="reset.css" rel="stylesheet" type="text/css" />
<link href="base.css" rel="stylesheet" type="text/css" />
<link href="style.css" rel="stylesheet" type="text/css" />
<script type="text/javascript" src="share.js"></script>
<script>
var interval = 5;
var remainTime = 60;

<% initWizardScreen4_1_1(); %>

function count()
{
	var obj = document.getElementById("time");
	if(interval > 0 && remainTime > 0)
	{
		obj.innerHTML = "<% multilang(LANG_PLEASE_WAIT_FOR); %>" + " " + remainTime + " " + "<% multilang(LANG_SECONDS); %>";
		remainTime--;
		interval--;
		setTimeout("count()", 1000);
	}
	else
	{
		document.Wizard4_1_1.submit();
	}
}

function load()
{
	count();
}
</script>
</head>
<body onLoad="load();">
<form action=/boaform/admin/formWizardScreen4_1_1 method=POST name="Wizard4_1_1">
<div class="data_common data_common_notitle">
<table>
	<tr>			
		<td align="center">
			<div style="font-size:32px;color:green"><% multilang(LANG_SETUP_CONNECTION_IS_PERFORMED); %></div>
			<div id="time" style="font-size:32px;color:green"><% multilang(LANG_PLEASE_WAIT_FOR); %> ... <% multilang(LANG_SECONDS); %></div>
			<div style="font-size:32px;color:red"><% multilang(LANG_DO_NOT_POWER_OFF_THE_DEVICE); %></div>
		</td>
	</tr>
</table>
</div>
</form>
</body>
</html>

