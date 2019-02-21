<%SendWebHeadStr(); %>
<title><% multilang(LANG_PORT_FORWARDING); %> - <% multilang(LANG_ADVANCED_SETTINGS); %></title>

<SCRIPT>

function PFWRemove() {
   with ( document.portfwAdvance ) {
      var arrSelected = new Array();
      var count = 0;
      for ( i = 0; i < lstApply.options.length; i++ ) {
         if ( lstApply.options[i].selected == true ) {
            arrSelected[count] = lstApply.options[i].value;
         }
         count++;
      }
      var x = 0;
      for (i = 0; i < lstApply.options.length; i++) {
         for (x = 0; x < arrSelected.length; x++) {
            if (lstApply.options[i].value == arrSelected[x]) {
               //varOpt = new Option(lstApply.options[i].text, lstApply.options[i].value);
               //lstAvail.options[lstAvail.length] = varOpt;
               
               // delete the option
               lstApply.options[i] = null;
            }
         }
      }
   }
}

function PFWAdd() {
   with ( document.portfwAdvance ) {
      var arrSelected = new Array();
      var count = 0;
      var y = 0;
      for ( i = 0; i < lstAvail.options.length; i++ ) {                
             if ( lstAvail.options[i].selected == true && lstApply.options.length == 0 ) {
                  arrSelected[count] = lstAvail.options[i].value;
                  count++;
            }                
      }
      
      var x = 0;
      for (i = 0; i < lstAvail.options.length; i++) {
         for (x = 0; x < arrSelected.length; x++) {
            if (lstAvail.options[i].value == arrSelected[x]) {
               varOpt = new Option(lstAvail.options[i].text, lstAvail.options[i].value);
               lstApply.options[lstApply.length] = varOpt;
               
               // delete the option
               //lstAvail.options[i] = null;
            }
         }
      }
   }
}

function PFWApply(obj) {
   //document.portfwAdvance.ruleApply.value="";    
   
   if (document.portfwAdvance.ip.value=="") {
	alert("<% multilang(LANG_LOCAL_IP_ADDRESS_CANNOT_BE_EMPTY); %>");
	document.portfwAdvance.ip.focus();
	return false;
   }   
   
   if (!checkHostIP(document.portfwAdvance.ip, 1))
	return false;
	
   if (document.portfwAdvance.lstApply.options.length == 0) {
	alert("<% multilang(LANG_RULE_CANNOT_BE_EMPTY_PLEASE_CHOOSE_ONE_GATEGORY_AND_SELECT_ONE_AVAILABLE_RULE_THEN_ADD_INTO_APPLIED_RULE); %>");
	return false;
   }
   
   with ( document.portfwAdvance ) {
      for (i = 0; i < lstApply.options.length; i++)
         ruleApply.value+=lstApply.options[i].value + ',';
      //for (i = 0; i < lstAvail.options.length; i++)
      //   itfsAvail.value+=lstAvail.options[i].value + ',';
   }

   obj.isclick = 1;
   postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	
   return true;
}

function postPFW(apply, applyval, avail, availval) {
   var interfaces;
   with ( document.portfwAdvance ) {
      interfaces = apply.split(',');
      itfvals = applyval.split(',');
      
      // clear a select box
      lstApply.options.length = 0;
      for ( i = 0; i < interfaces.length; i++ ) {
         if (interfaces[i] != '') {
            // create a new option
            lstApply.options[i] = new Option(interfaces[i], itfvals[i]);
         }
      }
      
      interfaces = avail.split(',');
      itfvals = availval.split(',');
      
       // clear a select box
      lstAvail.options.length = 0;
      for ( i = 0; i < interfaces.length; i++ ) {
         if (interfaces[i] != '') {
             // create a new option
            lstAvail.options[i] = new Option(interfaces[i], itfvals[i]);
         }
      }
   }
}

function deleteAllClick(obj)
{
	if ( !confirm('Do you really want to delete the all entries?') ) {
		return false;
	}
	else{
		obj.isclick = 1;
		postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
		return true;
	}
}

function on_submit(obj)
{
	obj.isclick = 1;
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	return true;
}

</SCRIPT>
</head>

<body>
<div class="intro_main ">
	<p class="intro_title"><% multilang(LANG_PORT_FORWARDING); %> - <% multilang(LANG_ADVANCED_SETTINGS); %></p>
</div>

<form action=/boaform/formPFWAdvance method=POST name="portfwAdvance">
<div class="data_common data_common_notitle">
   <table>
      <tr>
          <th><% multilang(LANG_CATEGORY); %>: </th>
          <td>
              <input type="radio" name=gategory value=0 onClick="postPFW('', '', 'PPTP,L2TP', '0,1')"><% multilang(LANG_VPN); %>&nbsp;&nbsp;  
          </td>
      </tr>   
   </table>  
</div>  

<div class="data_common data_common_notitle">
	<table>
		<tr>
			<th><% multilang(LANG_INTERFACE); %>:</th>
			<td>
				<select name="interface">
					<% if_wan_list("rt-any"); %>		
				</select>    
				<input type="hidden" value="" name="select_id">
			</td>
		</tr>   
		<tr>
			<th><% multilang(LANG_LOCAL); %> <% multilang(LANG_IP_ADDRESS); %>:</th>
			<td>
				<input type="text" name="ip" size="15" maxlength="15">			
			</td>		
		</tr>
	</table>   
</div>     

<div class="data_common data_common_notitle">
   <table>
      <tr>      
         <th><% multilang(LANG_AVAILABLE_RULES); %></th>
         <td></td>
         <th><% multilang(LANG_APPLIED_RULES); %></th>
      </tr>      
      <tr>
         <td>
             <select multiple name="lstAvail" size="8" style="width: 100px"></select>
         </td>
         <td>
            <table>
               <tr><td>
                  <input class="inner_btn" type="button" name="rmbtn" value="->" onClick="PFWAdd()" style="width: 30; height: 30">
               </td></tr>
               <tr><td>
                  <input class="inner_btn" type="button" name="adbtn" value="<-" onClick="PFWRemove()" style="width: 30; height: 30">
               </td></tr>
            </table>
         </td>
         <td>
             <select multiple name="lstApply" size="8" style="width: 100px"></select>	
         </td>
    </table>
</div>

<div class="btn_ctl">     
	<input class="link_bg" type=submit value="<% multilang(LANG_ADD); %>" name="save" onClick="return PFWApply(this)">&nbsp;&nbsp;
</div>     

<div class="column">
	<div class="column_title">
		<div class="column_title_left"></div>
			<p><% multilang(LANG_PORT_FORWARDING_ADVANCE_TABLE); %></p>
		<div class="column_title_right"></div>
	</div>
	<div class="data_common">
		<table>
			<% showPFWAdvTable(); %>
		</table>
	</div>
</div>

<div class="btn_ctl"> 
   <input type="hidden" name=ruleApply>
   <!--<input type="hidden" name=itfsAvail>-->
   <input type="hidden" value="/portfw-advance.asp" name="submit-url">
   <input class="link_bg" type="submit" value="<% multilang(LANG_DELETE_SELECTED); %>" name="delRule" onClick="return on_submit(this)">&nbsp;&nbsp;  
   <input class="link_bg" type="submit" value="<% multilang(LANG_DELETE_ALL); %>" name="delAllRule" onClick="return deleteAllClick(this)">&nbsp;&nbsp;&nbsp;
   <input type="hidden" name="postSecurityFlag" value="">
</div>

<script>
	document.portfwAdvance.gategory[0].checked = false;	
</script>
</form>
</blockquote>
</body>

</html>

