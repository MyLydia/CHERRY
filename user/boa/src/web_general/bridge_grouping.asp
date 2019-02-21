<%SendWebHeadStr(); %>
<title><% multilang(LANG_BRIDGE_GROUPING); %><% multilang(LANG_CONFIGURATION); %></title>

<script>
function btnRemove()
{
	with (document.bridgeGrouping) {
		for (i = 0; i < lstGrp.options.length; i++) {
			if (lstGrp.options[i].selected == true) {
				lstAvail.options.add(new Option(lstGrp.options[i].text,
									lstGrp.options[i].value));
				lstGrp.options.remove(i--);
			}
		}
	}
}

function btnAdd()
{
	with (document.bridgeGrouping) {
		for (i = 0; i < lstAvail.options.length; i++) {
			if (lstAvail.options[i].selected == true) {
				lstGrp.options.add(new Option(lstAvail.options[i].text,
									lstAvail.options[i].value));
				lstAvail.options.remove(i--);
			}
		}
	}
}

function btnApply()
{
	with (document.bridgeGrouping) {
		for (i = 0; i < lstGrp.options.length; i++)
			itfsGroup.value += lstGrp.options[i].value + ',';
		for (i = 0; i < lstAvail.options.length; i++)
			itfsAvail.value += lstAvail.options[i].value + ',';
	}

	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
}

function postit(groupitf, groupval, availitf, availval)
{
	var interfaces, itfvals;

	with (document.bridgeGrouping) {
		interfaces = groupitf.split(', ');
		itfvals = groupval.split(', ');
		lstGrp.options.length = 0;
		for (i = 0; i < interfaces.length; i++) {
			if (interfaces[i] != '') {
				lstGrp.options.add(new Option(interfaces[i], itfvals[i]))
			}
		}

		interfaces = availitf.split(', ');
		itfvals = availval.split(', ');
		lstAvail.options.length = 0;
		for (i = 0; i < interfaces.length; i++) {
			if (interfaces[i] != '') {
				lstAvail.options.add(new Option(interfaces[i], itfvals[i]));
			}
		}
	}
}
</script>
</head>

<body>
<div class="intro_main ">
	<p class="intro_title"><% multilang(Bridge Grouping); %> <% multilang(LANG_CONFIGURATION); %></p>
	<p class="intro_content"> <% multilang(LANG_TO_MANIPULATE_A_MAPPING_GROUP); %>:<br>
    <b>1.</b> <% multilang(LANG_SELECT_A_GROUP_FROM_THE_TABLE); %><br>
    <b>2.</b> <% multilang(LANG_SELECT_INTERFACES_FROM_THE_AVAILABLE_GROUPED_INTERFACE_LIST_AND_ADD_IT_TO_THE_GROUPED_AVAILABLE_INTERFACE_LIST_USING_THE_ARROW_BUTTONS_TO_MANIPULATE_THE_REQUIRED_MAPPING_OF_THE_PORTS); %><br>
    <b>3.</b> <% multilang(LANG_CLICK_APPLY_CHANGES_BUTTON_TO_SAVE_THE_CHANGES); %><br><br>
    <b><% multilang(LANG_NOTE_THAT_THE_SELECTED_INTERFACES_WILL_BE_REMOVED_FROM_THEIR_EXISTING_GROUPS_AND_ADDED_TO_THE_NEW_GROUP); %></b></p>
</div>

<form action=/boaform/formBridgeGrouping method=POST name="bridgeGrouping">
<div class="data_vertical data_common_notitle">
	 <div class="data_common ">
		<table>
		   <tr>
		      <th><% multilang(LANG_GROUPED_INTERFACES); %></th>
		      <th></th>
		      <th><% multilang(LANG_AVAILABLE_INTERFACES); %></th>
		   </tr>
		   <tr>
		      <td>
		          <select multiple name="lstGrp" size="8" style="width: 120px; height=150px"></select>
		      </td>
		      <td>
		         <table>
		            <tr><td>
		               <input type="button" name="rmbtn" value="->" onClick="btnRemove()" style="width: 30px; height: 30px">
		            </td></tr>
		            <tr><td>
		               <input type="button" name="adbtn" value="<-" onClick="btnAdd()" style="width: 30px; height: 30px">
		            </td></tr>
		         </table>
		      </td>
		      <td>
		          <select multiple name="lstAvail" size="8" style="width: 120px; height=150px"></select>
		      </td>
		   </tr>
		</table>
	</div>
</div>

<% itfGrpList(); %>

<div class="btn_ctl">
      <input type="hidden" name=itfsGroup>
      <input type="hidden" name=itfsAvail>
      <input class="link_bg" type=submit value="<% multilang(LANG_APPLY_CHANGES); %>" onClick=btnApply()>&nbsp;&nbsp;
      <input type="hidden" value="/bridge_grouping.asp" name="submit-url">
      <input type="hidden" name="postSecurityFlag" value="">
</div>
</form>
</blockquote>
</body>

</html>
