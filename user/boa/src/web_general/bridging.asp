<%SendWebHeadStr(); %>
<title><% multilang(LANG_BRIDGING); %><% multilang(LANG_CONFIGURATION); %></title>

<SCRIPT>
function saveChanges()
{
	if (checkDigit(document.bridge.ageingTime.value) == 0) {		
		alert('<% multilang(LANG_INVALID_AGEING_TIME); %>');
		document.bridge.ageingTime.focus();
		return false;
	}
	document.forms[0].save.isclick = 1;
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);	
	return true;
}

function fdbClick(url)
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

	window.open( url, 'FDBTbl', settings );
}
	
</SCRIPT>
</head>

<body>
<div class="intro_main ">
	<p class="intro_title"><% multilang(LANG_BRIDGING); %> <% multilang(LANG_CONFIGURATION); %></p>
	<p class="intro_content"><% multilang(LANG_THIS_PAGE_IS_USED_TO_CONFIGURE_THE_BRIDGE_PARAMETERS_HERE_YOU_CAN_CHANGE_THE_SETTINGS_OR_VIEW_SOME_INFORMATION_ON_THE_BRIDGE_AND_ITS_ATTACHED_PORTS); %></p>
</div>

<form action=/boaform/formBridging method=POST name="bridge">
<div class="data_common data_common_notitle">
	<table>
	  <tr>
	      <th width="30%"><% multilang(LANG_AGEING_TIME); %>:</th>
	      <td width="70%"><input type="text" name="ageingTime" size="15" maxlength="15" value=<% getInfo("bridge-ageingTime"); %>> (<% multilang(LANG_SECONDS); %>)</td>
	  </tr>
	  <tr>
	      <th>802.1d <% multilang(LANG_SPANNING_TREE); %>:</th>
	      <td>
	      	<input type="radio" value="0" name="stp" <% checkWrite("br-stp-0"); %>><% multilang(LANG_DISABLED); %>&nbsp;&nbsp;
	     	<input type="radio" value="1" name="stp" <% checkWrite("br-stp-1"); %>><% multilang(LANG_ENABLED); %>
	      </td>
	  </tr>
	</table>
</div>
<div class="btn_ctl">
      <input class="link_bg" type="submit" value="<% multilang(LANG_APPLY_CHANGES); %>" name="save" onClick="return saveChanges()">&nbsp;&nbsp;
      <input class="link_bg" type="button" value="<% multilang(LANG_SHOW_MACS); %>" name="fdbTbl" onClick="fdbClick('/fdbtbl.asp')">
      <input type="hidden" value="/bridging.asp" name="submit-url">
      <input type="hidden" name="postSecurityFlag" value="">
</div>
</form>
</body>
</html>
