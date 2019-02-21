<html>
<head>
<title>IP QoS <% multilang(LANG_CONFIGURATION); %></title>
<link rel="stylesheet" type="text/css" href="common_style.css"/>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">

<!--ç³»ç??¬å…±css-->

<!--ç³»ç??¬å…±?šæœ¬-->
<script language="javascript" src="common.js"></script>
<script language="javascript" type="text/javascript">
var policy = 1;
var rules = new Array();
var queues = new Array();
var totalBandwidth = 1000;
<% initQueuePolicy(); %>


function queue_display1() {
	var hrow=lstrc.rows[0];
	var hcell=hrow.cells[1];
	
	if(lstrc.rows){while(lstrc.rows.length > 1) lstrc.deleteRow(1);}
	for(var i = 0; i < queues.length; i++) {
		var row = lstrc.insertRow(i + 1);
		row.nowrap = true;
		row.vAlign = "center";
		row.align = "center";

		var cell = row.insertCell(0);
		cell.innerHTML = queues[i].qname;

		cell = row.insertCell(1);
		if (document.forms[0].queuepolicy[0].checked)
			cell.innerHTML = '<p>PRIO</p>';
		else if(document.forms[0].queuepolicy[1].checked)
			cell.innerHTML = '<p>WRR</p>';
//		else
//			cell.innerHTML = (i<hqueue)?('<p>PRIO</p>'):('<p>WRR</p>');
		cell = row.insertCell(2);
		if (document.forms[0].queuepolicy[0].checked)
			cell.innerHTML = queues[i].prio;
		else if(document.forms[0].queuepolicy[1].checked)
			cell.innerHTML = '<p>--</p>';
//		else
//			cell.innerHTML = (i<hqueue)?(queues[i].prio):('<p>--</p>');

		cell = row.insertCell(3);
		if (document.forms[0].queuepolicy[0].checked)
			cell.innerHTML = '<p>--</p>';
		else if(document.forms[0].queuepolicy[1].checked)
			cell.innerHTML = "<input type=\"text\" name=w" + i + " value=" + queues[i].weight + " size=3>";
//		else
//			cell.innerHTML = (i<hqueue)?('<p>--</p>'):("<input type=\"text\" name=w" + i + " value=" + queues[i].weight + " size=3>");

		cell = row.insertCell(4);
		qcheck= queues[i].enable? " checked":"";
		cell.innerHTML = "<input type=\"checkbox\" name=qen" + i + qcheck + ">";

		cell = row.insertCell(5);
		cell.innerHTML = "<input type=\"text\" name=shaping" + i + " id=shaping" + i + " value=" + queues[i].shaping + " size=6> bps";
	}

	document.getElementById('displayTotalBandwidth').innerHTML=
			'<p><% multilang(LANG_TOTAL_BANDWIDTH_LIMIT); %>:<input type="text" name="totalbandwidth" id="totalbandwidth" value="1005">Kb</p>';
	document.forms[0].totalbandwidth.value = totalBandwidth;

	document.all.bandwidth_defined[userDefinedBandwidth].checked = true;
	
}

function bandwidth_defined_check(){

	if (document.all.bandwidth_defined[1].checked)	
	{	
		/* Enable user defined mode */
		document.forms[0].totalbandwidth.disabled = false;
	}
	else 
	{	
		document.forms[0].totalbandwidth.disabled = true;
	}
	
}

function on_init(){
	with(document.forms[0]){
		if(policy != 0 && policy !=1)
			policy = 0;
		queuepolicy[policy].checked = true;
		qosen[qosEnable].checked = true;
		qosPly.style.display = qosEnable==0 ? "none":"block";		
	}
	queue_display1();
	bandwidth_defined_check();	
}

function on_save() {
	with(document.forms[0]) {
		var sbmtstr = "";
		if(queuepolicy[0].checked==true)
			sbmtstr = "policy=0";
		else
			sbmtstr = "policy=1";

		d = parseInt(document.forms[0].totalbandwidth.value, 10);
		if(d<0){
			alert("<% multilang(LANG_INVALID_TOTAL_BANDWIDTH_LIMIT); %>");
			document.forms[0].totalbandwidth.focus();
			return false;
		}

		var i = 0;
		for (i = 0; i < queues.length; i++) {
			var shapingid = "shaping" + i;
			if ((document.getElementById(shapingid).value == "") || 
				(document.getElementById(shapingid).value != 0 && document.getElementById(shapingid).value < 8000)){
				alert("<% multilang(LANG_INVALID_SHAPING_RATE); %>");
				return false;
			}
		}

		lst.value = sbmtstr;
		submit();
	}	
}

function qosen_click() {
	document.all.qosPly.style.display = document.all.qosen[0].checked ? "none":"block";
}

function qpolicy_click() {
	queue_display1();
	bandwidth_defined_check();
}

</script>
</head>
<body onLoad="on_init();">
<blockquote>
	<DIV align="left" style="padding-left:20px; padding-top:5px;">
		<h2 class="page_title">IP QoS <% multilang(LANG_CONFIGURATION); %></h2>
		<form id="form" action="/boaform/admin/formQosPolicy" method="post">		  

		<table>
			<tr><td><hr size=1 noshade align=top></td></tr>
		</table>
		<table>
		  	<tr>
		  		<th><% multilang(LANG_IP_QOS); %></th>
					<td><font size=2><input type="radio"  name=qosen value=0 onClick=qosen_click();><% multilang(LANG_DISABLE); %></td>	
					<td><font size=2><input type="radio"  name=qosen value=1 onClick=qosen_click();><% multilang(LANG_ENABLE); %></td>	
			</tr>
		  </table>
		 
		  <div  id="qosPly"  style="display:none">
		  <p><strong>QoS <% multilang(LANG_QUEUE_CONFIG); %></strong></p>
		  <p><% multilang(LANG_PAGE_DESC_CONFIGURE_QOS_POLICY); %></p>
		  <table>
		  	<tr>
				<th><% multilang(LANG_POLICY); %>:</th>
				<td><font size=2><input type="radio"  name="queuepolicy" value="prio" onClick=qpolicy_click();><% multilang(LANG_PRIO); %></td>	
				<td><font size=2><input type="radio"  name="queuepolicy" value="wrr" onClick=qpolicy_click();><% multilang(LANG_WRR); %></td>	
			</tr>
		  </table>
		  <table class="flat" id="lstrc" border="1" cellpadding="0" cellspacing="1" width=30%>
			<tr class="hdb" align="center" nowrap bgcolor="#CCCCCC">
				<td><font size=2><% multilang(LANG_QUEUE); %></td>
				<td><font size=2><% multilang(LANG_POLICY); %></td>
				<td><font size=2><% multilang(LANG_PRIORITY); %></td>
				<td><font size=2><% multilang(LANG_WEIGHT); %></td>
				<td><font size=2><% multilang(LANG_ENABLE); %></td>
				<td><font size=2><% multilang(LANG_RATE); %></td>
			</tr>
		  </table>
		  <br>

		  <p><strong>QoS Bandwidth Config</strong></p>
		  <p><% multilang(LANG_PAGE_DESC_CONFIGURE_BANDWIDTH); %></p>
		<table>
		  	<tr>
	  			<th><% multilang(LANG_USER_DEFINED_BANDWIDTH); %>:</th>
				<td><font size=2><input type="radio"  name=bandwidth_defined value=0 onClick=bandwidth_defined_check();>Disable</td>	
				<td><font size=2><input type="radio"  name=bandwidth_defined value=1 onClick=bandwidth_defined_check();>Enable</td>	
			</tr>
			<tr>
				<td ID="displayTotalBandwidth"></td>
			</tr>
		  </table>
		  </div>		  

		  <br><br>
		  <input type="button" class="button" value="<% multilang(LANG_APPLY_CHANGES); %>" onClick="on_save();">
		  <input type="hidden" id="lst" name="lst" value="">
		  <input type="hidden" name="submit-url" value="/net_qos_imq_policy.asp">
		</form>
	</DIV>
</blockquote>
</body>
</html>
