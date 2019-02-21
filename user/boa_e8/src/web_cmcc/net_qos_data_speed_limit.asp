<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<!--系统默认模板-->
<HTML>
<HEAD>
<TITLE>限速配置</TITLE>
<META http-equiv=pragma content=no-cache>
<META http-equiv=cache-control content="no-cache, must-revalidate">
<META http-equiv=content-type content="text/html; charset=gbk">
<META http-equiv=content-script-type content=text/javascript>
<!--系统公共css-->
<STYLE type=text/css>
@import url(/style/default.css);
</STYLE>
<!--系统公共脚本-->
<SCRIPT language="javascript" src="common.js"></SCRIPT>
<SCRIPT language="javascript" type="text/javascript">
var iffs = new it_nr("");
<% initQosLanif(); %>

var rule_mode_up = 0;
var rule_mode_down = 0;
var rule_intf_up = new Array();
var rule_intf_down = new Array();
var rule_vlan_up = new Array();
var rule_vlan_down = new Array();
var rule_ip_up = new Array();
var rule_ip_down = new Array();
<% initQosSpeedLimitRule(); %>

function rule_display(table_id, rule_array)
{
	with (document.forms[0])
	{
		var table_element = document.getElementById(table_id);
		if (table_element.rows) {
			while (table_element.rows.length > 1) {
				table_element.deleteRow(1);
			}
		}

		for (var i = 0; i < rule_array.length; i++) {
			var row = table_element.insertRow(i + 1);
			row.align = "center";

			var cell = row.insertCell(0);
			if (rule_array == rule_intf_up || rule_array == rule_intf_down) {
				cell.innerHTML = iffs[rule_array[i].if_id];
			}
			else if (rule_array == rule_vlan_up || rule_array == rule_vlan_down) {
				cell.innerHTML = rule_array[i].vlan;
			}
			else if (rule_array == rule_ip_up || rule_array == rule_ip_down) {
				cell.innerHTML = rule_array[i].ip_start + " - " + rule_array[i].ip_end;
			}

			cell = row.insertCell(1);
			cell.innerHTML = rule_array[i].speed_unit;

			if (rule_array == rule_intf_up) {
				cell = row.insertCell(2);
				cell.innerHTML = "<input type=\"button\" class=\"btnsaveup\" onclick=\"showInterfaceEdit('up', 'edit', "+ rule_array[i].idx +")\" value=\"Edit\">";

				cell = row.insertCell(3);
				cell.innerHTML = "<input type=\"button\" class=\"BtnDel\" onclick=\"showInterfaceEdit('up', 'del', "+ rule_array[i].idx +")\" value=\"删除\">";
			}
			else if (rule_array == rule_intf_down) {
				cell = row.insertCell(2);
				cell.innerHTML = "<input type=\"button\" class=\"btnsaveup\" onclick=\"showInterfaceEdit('down', 'edit', "+ rule_array[i].idx +")\" value=\"Edit\">";

				cell = row.insertCell(3);
				cell.innerHTML = "<input type=\"button\" class=\"BtnDel\" onclick=\"showInterfaceEdit('down', 'del', "+ rule_array[i].idx +")\" value=\"删除\">";
			}
			else if (rule_array == rule_vlan_up) {
				cell = row.insertCell(2);
				cell.innerHTML = "<input type=\"button\" class=\"btnsaveup\" onclick=\"showVlanTagEdit('up', 'edit', "+ rule_array[i].idx +")\" value=\"Edit\">";

				cell = row.insertCell(3);
				cell.innerHTML = "<input type=\"button\" class=\"BtnDel\" onclick=\"showVlanTagEdit('up', 'del', "+ rule_array[i].idx +")\" value=\"删除\">";
			}
			else if (rule_array == rule_vlan_down) {
				cell = row.insertCell(2);
				cell.innerHTML = "<input type=\"button\" class=\"btnsaveup\" onclick=\"showVlanTagEdit('down', 'edit', "+ rule_array[i].idx +")\" value=\"Edit\">";

				cell = row.insertCell(3);
				cell.innerHTML = "<input type=\"button\" class=\"BtnDel\" onclick=\"showVlanTagEdit('down', 'del', "+ rule_array[i].idx +")\" value=\"删除\">";
			}
			else if (rule_array == rule_ip_up) {
				cell = row.insertCell(2);
				cell.innerHTML = "<input type=\"button\" class=\"btnsaveup\" onclick=\"showIPEdit('up', 'edit', "+ rule_array[i].idx +")\" value=\"Edit\">";

				cell = row.insertCell(3);
				cell.innerHTML = "<input type=\"button\" class=\"BtnDel\" onclick=\"showIPEdit('up', 'del', "+ rule_array[i].idx +")\" value=\"删除\">";
			}
			else if (rule_array == rule_ip_down) {
				cell = row.insertCell(2);
				cell.innerHTML = "<input type=\"button\" class=\"btnsaveup\" onclick=\"showIPEdit('down', 'edit', "+ rule_array[i].idx +")\" value=\"Edit\">";

				cell = row.insertCell(3);
				cell.innerHTML = "<input type=\"button\" class=\"btndeleup\" onclick=\"showIPEdit('down', 'del', "+ rule_array[i].idx +")\" value=\"删除\">";
			}
		}
	}
}

function rule_edit_display(rule_array, rule_idx)
{
	with (document.forms[0])
	{
		for (var i = 0; i < rule_array.length; i++) {
			if (rule_array[i].idx == rule_idx) {
				if (rule_array == rule_intf_up) {
					setSelect("InterfaceName_up", rule_array[i].if_id);
					InterfaceSpeed_up.value = rule_array[i].speed_unit;
				}
				else if (rule_array == rule_intf_down) {
					setSelect("InterfaceName_down", rule_array[i].if_id);
					InterfaceSpeed_down.value = rule_array[i].speed_unit;
				}
				else if (rule_array == rule_vlan_up) {
					VlanTagValue_up.value = rule_array[i].vlan;
					VlanTagSpeed_up.value = rule_array[i].speed_unit;
				}
				else if (rule_array == rule_vlan_down) {
					VlanTagValue_down.value = rule_array[i].vlan;
					VlanTagSpeed_down.value = rule_array[i].speed_unit;
				}
				else if (rule_array == rule_ip_up) {
					IP_Start_up.value = rule_array[i].ip_start;
					IP_End_up.value = rule_array[i].ip_end;
					IPSpeed_up.value = rule_array[i].speed_unit;
				}
				else if (rule_array == rule_ip_down) {
					IP_Start_down.value = rule_array[i].ip_start;
					IP_End_down.value = rule_array[i].ip_end;
					IPSpeed_down.value = rule_array[i].speed_unit;
				}
				return;
			}
		}
	}
}

function on_init()
{
	with (document.forms[0])
	{
		setSelect("ModeSwitch_up", rule_mode_up);
		ModeChange('up');

		setSelect("ModeSwitch_down", rule_mode_down);
		ModeChange('down');

		rule_display('InterfaceTable_up', rule_intf_up);
		rule_display('VlanTagTable_up', rule_vlan_up);
		rule_display('IPTable_up', rule_ip_up);
		rule_display('InterfaceTable_down', rule_intf_down);
		rule_display('VlanTagTable_down', rule_vlan_down);
		rule_display('IPTable_down', rule_ip_down);

		var intf_select_up = document.getElementById('InterfaceName_up');
		var intf_select_down = document.getElementById('InterfaceName_down');
		for (var i in iffs)
		{
			if (i == "name" || (typeof iffs[i] != "string" && typeof iffs[i] != "number")) continue;
			intf_select_up.options.add(new Option(iffs[i], i));
			intf_select_down.options.add(new Option(iffs[i], i));
		}
	}
}

function ModeChange(direction)
{
	with (document.forms[0])
	{
		if (direction == "up")
		{
			var ModeIndex = document.getElementById('ModeSwitch_up').selectedIndex;
			if (ModeIndex == 0)
			{
				showhide('InterfaceLimit_up', 0);
				showhide('InterfaceEdit_up', 0);
				showhide('VlanTagLimit_up', 0);
				showhide('VlanTagEdit_up', 0);
				showhide('IPLimit_up', 0);
				showhide('IPEdit_up', 0);
			}
			else if (ModeIndex == 1)
			{
				if (rule_mode_up==0&&!confirm('将自动关闭"SP/WRR"调度策略')) 
				{ 
						setSelect("ModeSwitch_up", rule_mode_up);
						return; 
				}			
				showhide('InterfaceLimit_up', 1);
				showhide('InterfaceEdit_up', 0);
				showhide('VlanTagLimit_up', 0);
				showhide('VlanTagEdit_up', 0);
				showhide('IPLimit_up', 0);
				showhide('IPEdit_up', 0);
			}
			else if (ModeIndex == 2)
			{
				if (rule_mode_up==0&&!confirm('将自动关闭"SP/WRR"调度策略')) 
				{ 
						setSelect("ModeSwitch_up", rule_mode_up);
						return; 
				}	
				showhide('InterfaceLimit_up', 0);
				showhide('InterfaceEdit_up', 0);
				showhide('VlanTagLimit_up', 1);
				showhide('VlanTagEdit_up', 0);
				showhide('IPLimit_up', 0);
				showhide('IPEdit_up', 0);
			}
			else if (ModeIndex == 3)
			{
				if (rule_mode_up==0&&!confirm('将自动关闭"SP/WRR"调度策略')) 
				{ 
						setSelect("ModeSwitch_up", rule_mode_up);
						return; 
				}	
				showhide('InterfaceLimit_up', 0);
				showhide('InterfaceEdit_up', 0);
				showhide('VlanTagLimit_up', 0);
				showhide('VlanTagEdit_up', 0);
				showhide('IPLimit_up', 1);
				showhide('IPEdit_up', 0);
			}
		}
		else if (direction == "down")
		{
			var ModeIndex = document.getElementById('ModeSwitch_down').selectedIndex;
			if (ModeIndex == 0)
			{
				showhide('InterfaceLimit_down', 0);
				showhide('InterfaceEdit_down', 0);
				showhide('VlanTagLimit_down', 0);
				showhide('VlanTagEdit_down', 0);
				showhide('IPLimit_down', 0);
				showhide('IPEdit_down', 0);
			}
			else if (ModeIndex == 1)
			{
				showhide('InterfaceLimit_down', 1);
				showhide('InterfaceEdit_down', 0);
				showhide('VlanTagLimit_down', 0);
				showhide('VlanTagEdit_down', 0);
				showhide('IPLimit_down', 0);
				showhide('IPEdit_down', 0);
			}
			else if (ModeIndex == 2)
			{
				showhide('InterfaceLimit_down', 0);
				showhide('InterfaceEdit_down', 0);
				showhide('VlanTagLimit_down', 1);
				showhide('VlanTagEdit_down', 0);
				showhide('IPLimit_down', 0);
				showhide('IPEdit_down', 0);
			}
			else if (ModeIndex == 3)
			{
				showhide('InterfaceLimit_down', 0);
				showhide('InterfaceEdit_down', 0);
				showhide('VlanTagLimit_down', 0);
				showhide('VlanTagEdit_down', 0);
				showhide('IPLimit_down', 1);
				showhide('IPEdit_down', 0);
			}
		}
	}
}

function showInterfaceEdit(direction, act, idx)
{
	with (document.forms[0])
	{
		if (direction == "up")
		{
			ruleAction_up.value = act;
			ruleIndex_up.value = idx;

			if (act == "add")
			{
				showhide('InterfaceEdit_up', 1);
				InterfaceName_up.selectedIndex = 0;
				InterfaceSpeed_up.value = 0;
			}
			else if (act == "edit")
			{
				rule_edit_display(rule_intf_up, idx);
				showhide('InterfaceEdit_up', 1);
			}
			else if (act == "del")
			{
				if (!confirm("您确认要删除吗?")) {
					return false;
				}
				ruleDirection.value = direction;
				submitAction.value = "rule";
				submit();
			}
		}
		else if (direction == "down")
		{
			ruleAction_down.value = act;
			ruleIndex_down.value = idx;

			if (act == "add")
			{
				showhide('InterfaceEdit_down', 1);
				InterfaceName_down.selectedIndex = 0;
				InterfaceSpeed_down.value = 0;
			}
			else if (act == "edit")
			{
				rule_edit_display(rule_intf_down, idx);
				showhide('InterfaceEdit_down', 1);
			}
			else if (act == "del")
			{
				if (!confirm("您确认要删除吗?")) {
					return false;
				}
				ruleDirection.value = direction;
				submitAction.value = "rule";
				submit();
			}
		}
	}
}

function showVlanTagEdit(direction, act, idx)
{
	with (document.forms[0])
	{
		if (direction == "up")
		{
			ruleAction_up.value = act;
			ruleIndex_up.value = idx;


			if (act == "add")
			{
				showhide('VlanTagEdit_up', 1);
				VlanTagValue_up.value = 0;
				VlanTagSpeed_up.value = 0;
			}
			else if (act == "edit")
			{
				rule_edit_display(rule_vlan_up, idx);
				showhide('VlanTagEdit_up', 1);
			}
			else if (act == "del")
			{
				if (!confirm("您确认要删除吗?")) {
					return false;
				}
				ruleDirection.value = direction;
				submitAction.value = "rule";
				submit();
			}
		}
		else if (direction == "down")
		{
			ruleAction_down.value = act;
			ruleIndex_down.value = idx;

			if (act == "add")
			{
				showhide('VlanTagEdit_down', 1);
				VlanTagValue_down.value = 0;
				VlanTagSpeed_down.value = 0;
			}
			else if (act == "edit")
			{
				rule_edit_display(rule_vlan_down, idx);
				showhide('VlanTagEdit_down', 1);
			}
			else if (act == "del")
			{
				if (!confirm("您确认要删除吗?")) {
					return false;
				}
				ruleDirection.value = direction;
				submitAction.value = "rule";
				submit();
			}
		}
	}
}

function showIPEdit(direction, act, idx)
{
	with (document.forms[0])
	{
		if (direction == "up")
		{
			ruleAction_up.value = act;
			ruleIndex_up.value = idx;

			if (act == "add")
			{
				showhide('IPEdit_up', 1);
				IP_Start_up.value = 0;
				IP_End_up.value = 0;
				IPSpeed_up.value = 0;
			}
			else if (act == "edit")
			{
				rule_edit_display(rule_ip_up, idx);
				showhide('IPEdit_up', 1);
			}
			else if (act == "del")
			{
				if (!confirm("您确认要删除吗?")) {
					return false;
				}
				ruleDirection.value = direction;
				submitAction.value = "rule";
				submit();
			}
		}
		else if (direction == "down")
		{
			ruleAction_down.value = act;
			ruleIndex_down.value = idx;

			if (act == "add")
			{
				showhide('IPEdit_down', 1);
				IP_Start_down.value = 0;
				IP_End_down.value = 0;
				IPSpeed_down.value = 0;
			}
			else if (act == "edit")
			{
				rule_edit_display(rule_ip_down, idx);
				showhide('IPEdit_down', 1);
			}
			else if (act == "del")
			{
				if (!confirm("您确认要删除吗?")) {
					return false;
				}
				ruleDirection.value = direction;
				submitAction.value = "rule";
				submit();
			}
		}
	}
}

function isInvalidSpeed(s)
{
	if (isNaN(parseInt(s, 10)) || parseInt(s, 10) <= 0 || parseInt(s, 10) > 2047) {
		return true;
	}
	return false;
}

function isInvalidVLAN(s)
{
	if (s == "untagged") {
		return false;
	}

	if (isNaN(parseInt(s, 10)) || parseInt(s, 10) < 1 || parseInt(s, 10) > 4096) {
		return true;
	}
	return false;
}

function RuleSubmit(direction)
{
	with (document.forms[0])
	{
		if (direction == "up")
		{
			var ModeIndex = document.getElementById('ModeSwitch_up').selectedIndex;
			if (ModeIndex == 1) // Interface
			{
				if (isInvalidSpeed(InterfaceSpeed_up.value)) {
					alert("请填入大于0的限速值，范围介于1-2047");
					return false;
				}
			}
			else if (ModeIndex == 2) // VlanTag
			{
				if (isInvalidVLAN(VlanTagValue_up.value)) {
					alert("请填入正确的VLAN或者填入untagged");
					return false;
				}

				if (isInvalidSpeed(VlanTagSpeed_up.value)) {
					alert("请填入大于0的限速值，范围介于1-2047");
					return false;
				}
			}
			else if (ModeIndex == 3) // IP
			{
				if((!sji_checkvip(IP_Start_up.value) && !isIPv6(IP_Start_up.value)) || (!sji_checkvip(IP_End_up.value) && !isIPv6(IP_End_up.value))){
					alert("IP地址格式不正确，请填写正确的IP地址");
					return false;
				}

				if (isInvalidSpeed(IPSpeed_up.value)) {
					alert("请填入大于0的限速值，范围介于1-2047");
					return false;
				}
			}
			else {
				return false;
			}
		}
		else if (direction == "down")
		{
			var ModeIndex = document.getElementById('ModeSwitch_down').selectedIndex;
			if (ModeIndex == 1) // Interface
			{
				if (isInvalidSpeed(InterfaceSpeed_down.value)) {
					alert("请填入大于0的限速值，范围介于1-2047");
					return false;
				}
			}
			else if (ModeIndex == 2) // VlanTag
			{
				if (isInvalidVLAN(VlanTagValue_down.value)) {
					alert("请填入正确的VLAN或者填入untagged");
					return false;
				}

				if (isInvalidSpeed(VlanTagSpeed_down.value)) {
					alert("请填入大于0的限速值，范围介于1-2047");
					return false;
				}
			}
			else if (ModeIndex == 3) // IP
			{
				if((!sji_checkvip(IP_Start_down.value) && !isIPv6(IP_Start_down.value)) || (!sji_checkvip(IP_End_down.value) && !isIPv6(IP_End_down.value))){
					alert("IP地址格式不正确，请填写正确的IP地址");
					return false;
				}

				if (isInvalidSpeed(IPSpeed_down.value)) {
					alert("请填入大于0的限速值，范围介于1-2047");
					return false;
				}
			}
			else {
				return false;
			}
		}

		ruleDirection.value = direction;
		submitAction.value = "rule";
		submit();
	}
}

function ModeSubmit()
{
	with (document.forms[0])
	{
		submitAction.value = "mode";
		submit();
	}
}
function clickPage(filename)
{
			location.replace(filename);
}
</SCRIPT>
</HEAD>

<!-------------------------------------------------------------------------------------->
<!--主页代码-->
<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000" onLoad="on_init();">
	<blockquote>
			<form action=/boaform/admin/formQosSpeedLimit method=POST name="form">
<!-------------------------------------------------------------------------------------->
				<table border="0" cellpadding="2" cellspacing="0">
					<tr>
						<td>上行数据限速模式:</td>
						<td>
							<select id="ModeSwitch_up" size="1" name="ModeSwitch_up" onchange="ModeChange('up')">
								<option value="0">关闭</option>
								<option value="1">基于用户接口限速</option>
								<option value="2">基于用户侧VLAN限速</option>
								<option value="3">基于用户侧设备IP地址段限速</option>
							</select>
						</td>
					</tr>
				</table>

				<div id="InterfaceLimit_up">
					<table class="flat" id="InterfaceTable_up" border="1" cellpadding="1" cellspacing="1" width="100%">
						<tbody>
							<tr>
								<td align="center" width="50%">LAN/SSID</td>
								<td align="center" width="20%">限速(单位：512Kbps)</td>
								<td align="center" width="15%">修改</td>
								<td align="center" width="15%">删除</td>
							</tr>
						</tbody>
					</table>
					<table>
						<tbody>
							<tr>
								<td>
									<input type="button" class="btnaddup" onclick="showInterfaceEdit('up', 'add', -1)" value="添加">
								</td>
							</tr>
						</tbody>
					</table>
				</div>
				<div id="InterfaceEdit_up">
					<table>
						<tbody>
							<tr>
								<td>LAN/SSID：</td>
								<td>
									<select size="1" id="InterfaceName_up" name="InterfaceName_up">
									</select>
								</td>
							</tr>
						</tbody>
					</table>
					<table>
						<tbody>
							<tr>
								<td>限速：</td>
								<td>
									<input name="InterfaceSpeed_up" type="text" id="InterfaceSpeed_up" value="0" size="10" maxlength="10">
								</td>
							</tr>
						</tbody>
					</table>
					<table>
						<tbody>
							<tr>
								<td>
									<input type="button" class="btnsaveup" onclick="RuleSubmit('up')" value="提交">
								</td>
							</tr>
						</tbody>
					</table>
				</div>

				<div id="VlanTagLimit_up">
					<table class="flat" id="VlanTagTable_up" border="1" cellpadding="1" cellspacing="1" width="100%">
						<tbody>
							<tr align="middle">
								<td align="center" width="50%">VLAN</td>
								<td align="center" width="20%">限速(单位：512Kbps)</td>
								<td align="center" width="15%">修改</td>
								<td align="center" width="15%">删除</td>
							</tr>
						</tbody>
					</table>
					<table>
						<tbody>
							<tr>
								<td>
									<input type="button" class="btnaddup" onclick="showVlanTagEdit('up', 'add', -1)" value="添加">
								</td>
							</tr>
						</tbody>
					</table>
				</div>
				<div id="VlanTagEdit_up">
					<table>
						<tbody>
						<tr>
							<td>VLAN：</td>
							<td>
								<input name="VlanTagValue_up" type="text" id="VlanTagValue_up" value="0" size="15" maxlength="15">
							</td>
						</tr>
						</tbody>
					</table>
					<table>
						<tbody>
							<tr>
								<td>限速：</td>
								<td>
									<input name="VlanTagSpeed_up" type="text" id="VlanTagSpeed_up" value="0" size="10" maxlength="10">
								</td>
							</tr>
						</tbody>
					</table>
					<table>
						<tbody>
							<tr>
								<td>
									<input type="button" class="btnsaveup" onclick="RuleSubmit('up')" value="提交">
								</td>
							</tr>
						</tbody>
					</table>
				</div>

				<div id="IPLimit_up">
					<table class="flat" id="IPTable_up" border="1" cellpadding="1" cellspacing="1" width="100%">
						<tbody>
							<tr align="middle">
								<td align="center" width="50%">IP范围</td>
								<td align="center" width="20%">限速(单位：512Kbps)</td>
								<td align="center" width="15%">修改</td>
								<td align="center" width="15%">删除</td>
							</tr>
						</tbody>
					</table>
					<table>
						<tbody>
							<tr>
								<td>
									<input type="button" class="btnaddup" onclick="showIPEdit('up', 'add', -1)" value="添加">
								</td>
							</tr>
						</tbody>
					</table>
				</div>
				<div id="IPEdit_up">
					<table>
						<tbody>
							<tr>
								<td>IP范围：</td>
								<td>
									<input name="IP_Start_up" type="text" id="IP_Start_up" value="0" size="20" maxlength="39">
								</td>
								<td>-</td>
								<td>
									<input name="IP_End_up" type="text" id="IP_End_up" value="0" size="20" maxlength="39">
								</td>
							</tr>
						</tbody>
					</table>
					<table>
						<tbody>
							<tr>
								<td>限速：</td>
								<td>
									<input name="IPSpeed_up" type="text" id="IPSpeed_up" value="0" size="10" maxlength="10">
								</td>
							</tr>
						</tbody>
					</table>
					<table>
						<tbody>
							<tr>
								<td>
									<input type="button" class="btnsaveup" onclick="RuleSubmit('up')" value="提交">
								</td>
							</tr>
						</tbody>
					</table>
				</div>
<!-------------------------------------------------------------------------------------->
				<br><br>
<!-------------------------------------------------------------------------------------->
				<table border="0" cellpadding="2" cellspacing="0">
					<tr>
						<td>下行数据限速模式:</td>
						<td>
							<select id="ModeSwitch_down" size="1" name="ModeSwitch_down" onchange="ModeChange('down')">
								<option value="0">关闭</option>
								<option value="1">基于用户接口限速</option>
								<option value="2">基于用户侧VLAN限速</option>
								<option value="3">基于用户侧设备IP地址段限速</option>
							</select>
						</td>
					</tr>
				</table>

				<div id="InterfaceLimit_down">
					<table class="flat" id="InterfaceTable_down" border="1" cellpadding="1" cellspacing="1" width="100%">
						<tbody>
							<tr>
								<td align="center" width="50%">LAN/SSID</td>
								<td align="center" width="20%">限速(单位：512Kbps)</td>
								<td align="center" width="15%">修改</td>
								<td align="center" width="15%">删除</td>
							</tr>
						</tbody>
					</table>
					<table>
						<tbody>
							<tr>
								<td>
									<input type="button" class="btnaddup" onclick="showInterfaceEdit('down', 'add', -1)" value="添加">
								</td>
							</tr>
						</tbody>
					</table>
				</div>
				<div id="InterfaceEdit_down">
					<table>
						<tbody>
							<tr>
								<td>LAN/SSID：</td>
								<td>
									<select size="1" id="InterfaceName_down" name="InterfaceName_down">
									</select>
								</td>
							</tr>
						</tbody>
					</table>
					<table>
						<tbody>
							<tr>
								<td>限速：</td>
								<td>
									<input name="InterfaceSpeed_down" type="text" id="InterfaceSpeed_down" value="0" size="10" maxlength="10">
								</td>
							</tr>
						</tbody>
					</table>
					<table>
						<tbody>
							<tr>
								<td>
									<input type="button" class="btnsaveup" onclick="RuleSubmit('down')" value="提交">
								</td>
							</tr>
						</tbody>
					</table>
				</div>

				<div id="VlanTagLimit_down">
					<table class="flat" id="VlanTagTable_down" border="1" cellpadding="1" cellspacing="1" width="100%">
						<tbody>
							<tr align="middle">
								<td align="center" width="50%">VLAN</td>
								<td align="center" width="20%">限速(单位：512Kbps)</td>
								<td align="center" width="15%">修改</td>
								<td align="center" width="15%">删除</td>
							</tr>
						</tbody>
					</table>
					<table>
						<tbody>
							<tr>
								<td>
									<input type="button" class="btnaddup" onclick="showVlanTagEdit('down', 'add', -1)" value="添加">
								</td>
							</tr>
						</tbody>
					</table>
				</div>
				<div id="VlanTagEdit_down">
					<table>
						<tbody>
						<tr>
							<td>VLAN：</td>
							<td>
								<input name="VlanTagValue_down" type="text" id="VlanTagValue_down" value="0" size="15" maxlength="15">
							</td>
						</tr>
						</tbody>
					</table>
					<table>
						<tbody>
							<tr>
								<td>限速：</td>
								<td>
									<input name="VlanTagSpeed_down" type="text" id="VlanTagSpeed_down" value="0" size="10" maxlength="10">
								</td>
							</tr>
						</tbody>
					</table>
					<table>
						<tbody>
							<tr>
								<td>
									<input type="button" class="btnsaveup" onclick="RuleSubmit('down')" value="提交">
								</td>
							</tr>
						</tbody>
					</table>
				</div>

				<div id="IPLimit_down">
					<table class="flat" id="IPTable_down" border="1" cellpadding="1" cellspacing="1" width="100%">
						<tbody>
							<tr align="middle">
								<td align="center" width="50%">IP范围</td>
								<td align="center" width="20%">限速(单位：512Kbps)</td>
								<td align="center" width="15%">修改</td>
								<td align="center" width="15%">删除</td>
							</tr>
						</tbody>
					</table>
					<table>
						<tbody>
							<tr>
								<td>
									<input type="button" class="btnaddup" onclick="showIPEdit('down', 'add', -1)" value="添加">
								</td>
							</tr>
						</tbody>
					</table>
				</div>
				<div id="IPEdit_down">
					<table>
						<tbody>
							<tr>
								<td>IP范围：</td>
								<td>
									<input name="IP_Start_down" type="text" id="IP_Start_down" value="0" size="20" maxlength="39">
								</td>
								<td>-</td>
								<td>
									<input name="IP_End_down" type="text" id="IP_End_down" value="0" size="20" maxlength="39">
								</td>
							</tr>
						</tbody>
					</table>
					<table>
						<tbody>
							<tr>
								<td>限速：</td>
								<td>
									<input name="IPSpeed_down" type="text" id="IPSpeed_down" value="0" size="10" maxlength="10">
								</td>
							</tr>
						</tbody>
					</table>
					<table>
						<tbody>
							<tr>
								<td>
									<input type="button" class="btnsaveup" onclick="RuleSubmit('down')" value="提交">
									
								</td>
							</tr>
						</tbody>
					</table>
				</div>
<!-------------------------------------------------------------------------------------->
				<br><br><br>
				<input type="hidden" name="submitAction" value="">
				<input type="hidden" name="ruleDirection" value="">
				<input type="hidden" name="ruleAction_up" value="">
				<input type="hidden" name="ruleIndex_up" value="">
				<input type="hidden" name="ruleAction_down" value="">
				<input type="hidden" name="ruleIndex_down" value="">
				<table width="828px">
					<tbody>
					<td colspan="2"><p align="center">
							<input id="btnOK" onclick="ModeSubmit();" src="/image/ok_cmcc.gif" type="image" border="0">&nbsp;&nbsp;
						<img id="btnCancel" onclick="clickPage('net_qos_data_speed_limit.asp')" src="/image/cancel_cmcc.gif" border="0">
					</p></td>
					</tbody>
				</table>
				<input type="hidden" name="submit-url" value="/net_qos_data_speed_limit.asp">
			</form>
	</blockquote>
</body>
<%addHttpNoCache();%>
</html>
