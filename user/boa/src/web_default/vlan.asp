<html>
<! Copyright (c) Realtek Semiconductor Corp., 2003. All Rights Reserved. ->
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<title><% multilang(LANG_VLAN_SETTINGS); %></title>
<link rel="stylesheet" type="text/css" href="common_style.css" />
<SCRIPT language="javascript" src="/common.js"></SCRIPT>
<script type="text/javascript" src="share.js">
</script>
<SCRIPT>
var vlan_manu_pri= <% fmvlan_checkWrite("vlan_manu_tag_pri"); %>;
function vlan_cfg_type_change()
{
	with (document.forms[0])
	{
		if(vlan_cfg_type[0].checked == true){
			disableRadioGroup(vlan_manu_mode);
			vlan_manu_tag_pri.disabled = true;
			disableTextField(vlan_manu_tag_vid);
		}
		else{
			enableRadioGroup(vlan_manu_mode);
			vlan_manu_mode_change();
		}
	}
}
function vlan_manu_mode_change()
{
	with (document.forms[0])
	{
		if(vlan_manu_mode[1].checked == true){
			vlan_manu_tag_pri.disabled = false;
			enableTextField(vlan_manu_tag_vid);		
		}
		else{
			vlan_manu_tag_pri.disabled = true;
			disableTextField(vlan_manu_tag_vid);
		}
	}
}
function on_init()
{
	with (document.forms[0])
	{
		vlan_manu_tag_pri.value = vlan_manu_pri + 1;
		if(vlan_cfg_type[0].checked == true)
			refresh.disabled = false;
		else
			refresh.disabled = true;
			
	}
	vlan_cfg_type_change();
	
}
function saveChanges(obj)
{
	with (document.forms[0])
	{
		if (vlan_cfg_type[1].checked == true) {
			if(vlan_manu_mode[1].checked == true){
				if(vlan_manu_tag_vid.value == ""){
					alert("<% multilang(LANG_VID_CANNOT_BE_EMPTY); %>");
					vlan_manu_tag_vid.focus();
					return false;
				}
				if(vlan_manu_tag_pri.value == 0){
					alert("<% multilang(LANG_VLAN_PRIORITY_CANNOT_BE_EMPTY); %>");
					vlan_manu_tag_pri.focus();
					return false;
				}
			}
		}
	}

	obj.isclick = 1;
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	return true;
}

function on_submit(obj)
{
	obj.isclick = 1;
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	return true;
}
</SCRIPT>
</head>
<body onLoad="on_init();">
<blockquote>
<h2 class="page_title"><% multilang(LANG_VLAN_SETTINGS); %></h2>

<form action=/boaform/formVlan method=POST name="vlan">
<table>
  <tr><td><font size=2>
    <% multilang(LANG_PAGE_DESC_CONFIGURE_VLAN_SETTINGS); %>
  </font></td></tr>
  <tr><td><hr size=1 noshade align=top></td></tr>
</table>
<table>
<tr>
<td><input type="radio" name="vlan_cfg_type" value=0 OnClick="vlan_cfg_type_change()" <% fmvlan_checkWrite("vlan_cfg_type_auto"); %> ></td>
<th><% multilang(LANG_AUTO); %></th>
<td><input type="submit" value="<% multilang(LANG_REFRESH); %>" name="refresh" onClick="return on_submit(this)"></td>
</tr>
<tr style="vertical-align:top"><td height="50px" width="10%"></td><td height="50px" colspan=2><% omciVlanInfo(); %></td></tr>
<tr>
<td><input type="radio" name="vlan_cfg_type" value=1 OnClick="vlan_cfg_type_change()" <% fmvlan_checkWrite("vlan_cfg_type_manual"); %>></td>
<th><% multilang(LANG_MANUAL); %></th>
</tr>
</table>
<table>
<tr>
<td></td>
<td><input type="radio" name="vlan_manu_mode" value=0 OnClick="vlan_manu_mode_change()" <% fmvlan_checkWrite("vlan_manu_mode_trans"); %>></td>
<th><% multilang(LANG_TRANSPARENT_MODE); %></th>
</tr>
<tr>
<td></td>
<td><input type="radio" name="vlan_manu_mode" value=1 OnClick="vlan_manu_mode_change()" <% fmvlan_checkWrite("vlan_manu_mode_tag"); %>></td>
<th><% multilang(LANG_TAGGING_MODE); %>: </th>
<td><input type="text" name="vlan_manu_tag_vid" size="5" maxlength="5" value="<% fmvlan_checkWrite("vlan_manu_tag_vid"); %>">[0~4095]&nbsp;&nbsp;
<% multilang(LANG_VLAN_PRIORITY); %>:
	<select style="WIDTH: 60px" name="vlan_manu_tag_pri">
	<option value="0" > </option>
	<option value="1" > 0 </option>
	<option value="2" > 1 </option>
	<option value="3" > 2 </option>
	<option value="4" > 3 </option>
	<option value="5" > 4 </option>
	<option value="6" > 5 </option>
	<option value="7" > 6 </option>
	<option value="8" > 7 </option>
	</select>
</td>
</tr>
<tr>
<td></td>
<td><input type="radio" name="vlan_manu_mode" value=2 OnClick="vlan_manu_mode_change()" <% fmvlan_checkWrite("vlan_manu_mode_srv"); %>></td>
<th><% multilang(LANG_REMOTE_ACCESS_MODE); %></th>
</tr>
<tr>
<td></td>
<td><input type="radio" name="vlan_manu_mode" value=3 OnClick="vlan_manu_mode_change()" <% fmvlan_checkWrite("vlan_manu_mode_sp"); %>></td>
<th><% multilang(LANG_SPECIAL_CASE_MODE); %></td>
</tr>
</table>
<br>
      <input type="submit" value="<% multilang(LANG_APPLY_CHANGES); %>" name="save" onClick="return saveChanges(this)">
      <input type="hidden" value="/vlan.asp" name="submit-url">
      <input type="hidden" name="postSecurityFlag" value="">
</form>
</blockquote>
</body>

</html>

