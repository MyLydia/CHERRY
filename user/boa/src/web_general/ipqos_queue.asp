<%SendWebHeadStr(); %>
<title>IP <% multilang(LANG_QOS_QUEUE); %></title>

<script>
var qDesclist;
function addClick() {
	if (document.getElementById){  // DOM3 = IE5, NS6
		document.getElementById('queueadd').style.display = 'block';
	} else {
		if (document.layers == false) {// IE4
			document.all.queueadd.style.display = 'block';
		}
	}
}

function removeClick(rml) {
   var lst = '';
   if (rml.length > 0)
      for (i = 0; i < rml.length; i++) {
         if ( rml[i].checked == true )
            lst += rml[i].value + ', ';
      }
   else if ( rml.checked == true )
      lst = rml.value;
      
   document.qos.removeQueueList.value = lst;
   //document.write(document.qos.removeQueueList.value);
   //var loc = 'qosqueue.cmd?action=remove&rmLst=' + lst;

   //var code = 'location="' + loc + '"';
   //eval(code);

  <% ipQosQueueList("RemoveAddPostSecurityFlag"); %>
}

function savRebootClick(ebl) {
   var eblLst = '';
   if (ebl.length > 0)
      for (i = 0; i < ebl.length; i++) {
         if ( ebl[i].checked == true )
            eblLst += ebl[i].value + ', ';
      }
   else if ( ebl.checked == true )
      eblLst = ebl.value;
   
   document.qos.eblQueueList.value = eblLst;
   <% ipQosQueueList("SaveAddPostSecurityFlag"); %>
}

function updateDesc() {
	var currDesc;
	var i;
	var desc = qDesclist.split(";");
	var vpi_vci;
	var prior;
	
	for (i=0; i<desc.length; i++){
	  vpi_vci = desc[i].split(",");
	  with ( document.forms[0]) {
	        if(queueintf.value != vpi_vci[0])
	            continue;
	        prior = queuepriority.value-1;
	        if(prior <0)
	  		currDesc = vpi_vci[1] + "_p";
	  	else
	  		currDesc = vpi_vci[1] + "_p" + prior;
	  	queuedesc.value = currDesc;
	  }
	}
}

function btnApply() {

   with ( document.forms[0] ) {
      if ( queuedesc.value == "") {
         msg = 'Please input description for this queue.'
         alert(msg);
         return false;
      }
	  
      if ( queueenbl.selectedIndex == 0 ) {
         msg = 'Please select status for this queue.'
         alert(msg);
         return false;
      }

      if ( queueintf.selectedIndex == 0 ) {
         msg = 'Specify an egress interface for this queue.'
         alert(msg);
         return false;
      }

      if ( queuepriority.selectedIndex == 0 ) {
         msg = 'Please select precedence for this queue.'
         alert(msg);
         return false;
      }      

   }

   obj.isclick = 1;
   postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
   
   return true;
}

function btnCancel(){
	var loc = 'ipqos_queue.asp'
	var code = 'location="' + loc + '"';
	eval(code);
}

</SCRIPT>
</head>

<body>
<div class="intro_main ">
	<p class="intro_title">IP <% multilang(LANG_QOS_QUEUE); %></p>
	<p class="intro_content"> IP <% multilang(LANG_QOS_QUEUE); %><% multilang(LANG_CONFIGURATION); %></p>
</div>

<form action=/boaform/admin/formQueueAdd method=POST name=qos>
<div class="column">
	<div class="column_title">
		<div class="column_title_left"></div>
			<p><% multilang(LANG_QUEUE_CONFIG_LIST); %></p>
		<div class="column_title_right"></div>
	</div>
	<div class="data_common">
		<table>
			<% ipQosQueueList("queueList"); %>
		</table>
	</div>
</div>


<div class="btn_ctl">
	<input type="hidden" name=removeQueueList>
	<input type="hidden" name=eblQueueList>
	<input type="hidden" name=check>
	<input class="link_bg" type='button' onClick='addClick()' value='<% multilang(LANG_ADD); %>'>
	<!--
	<input type='submit' name="RemoveQueue" onClick=removeClick(this.form.removeQ) value='Remove'>
	<input type='submit' name="SaveAndReboot" onClick='savRebootClick(this.form.enableQ)' value='Save'></p>
	-->
	<% ipQosQueueList("QueueButton"); %>
</div>

<div id="queueadd" style="display:none">
	<div class="data_common data_common_notitle">
		<table id=body_header>
			<tr>
				<th><% multilang(LANG_QUEUE_DESCRIPTION); %>&nbsp;:</th>
				<td><input type="text" name="queuedesc" size="16" maxlength="30" readonly>                                                     
				</td>
			</tr>
			<tr>
				<th><% multilang(LANG_QUEUE_STATUS); %>&nbsp;:</th>
				<td>
					<select name='queueenbl' size="1">
						<option value="0">(<% multilang(LANG_CLICK_TO_SELECT); %>)
						<option value="1"> <% multilang(LANG_DISABLE); %>
						<option value="2"> <% multilang(LANG_ENABLE); %>
					</select>
				</td>
			</tr>
			<tr>
				<th><% multilang(LANG_QUEUE_INTERFACE); %>&nbsp;:</th>
				<td><select name='queueintf' size="1" onChange="updateDesc()">                                      
						<% if_wan_list("queueITF"); %>                  
					</select>
				</td>
			</tr>
			<tr>
				<th><% multilang(LANG_QUEUE_PRIORITY); %>&nbsp;:</th>
				<td>
					<select name='queuepriority' size="1" onChange="updateDesc()">
						<option value="0">(<% multilang(LANG_CLICK_TO_SELECT); %>)
						<option value="1"> 0
						<option value="2"> 1
						<option value="3"> 2        
						<option value="4"> 3
					</select>
				</td>
			</tr>                                   
		</table>
	</div>
	<div class="btn_ctl">
		<input class="link_bg" type='submit' onClick='return btnApply(this)' value='<% multilang(LANG_APPLY); %>' name="save">
		<input class="link_bg" type='button' onClick='return btnCancel()' value='<% multilang(LANG_CANCEL); %>'>
	</div>
</div>


<input type="hidden" value="/ipqos_queue.asp" name="submit-url">
<input type="hidden" name="postSecurityFlag" value="">
<script>
	<% initPage("qosQueue"); %>
</script>

</form>

<script type='text/javascript'>
if ( document.qos.check.value == "0")
	setTimeout("alert('Please create an Internet Setting with QoS enabled.');", 400);
</script>
</body>

</html>
