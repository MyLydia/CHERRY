<%SendWebHeadStr(); %>
<TITLE>Net vlan mapping</TITLE>

<SCRIPT >
var vlan_mapping_interface = <% checkWrite("vlan_mapping_interface"); %>;
<% initVlanRange(); %>
function getObj(id)
{
	return(document.getElementById(id));
}

function setValue(id,value)
{
	document.getElementById(id).value=value;
}

function getValue(id)
{
	return(document.getElementById(id).value);
}

function convertDisplay(name,col)
{
	//var port=["LAN1","LAN2","LAN3","LAN4","SSID1","SSID2","SSID3","SSID4","SSID5"];
	var port = vlan_mapping_interface;
	var mode=["Port Binding","VLAN Binding"];
	if(col==0){
		return port[name]||"";
	}
	else if(col==1){
		return mode[name]||mode[0];
	}
	else if(col==2){
		return getValue('VLAN'+name);
	}
	return value;
}

function ModifyInstance(obj, index)
{
  var mode_id="Mode"+index;
  if(getValue(mode_id) == 1)
  {
	document.getElementById("Frm_Mode").options[0].selected=true;
	document.getElementById("BindVlanRow").style.display = '';   
  }
  else
  {
    document.getElementById("Frm_Mode").options[1].selected=true;	
	document.getElementById("BindVlanRow").style.display = 'none'; 
  }

  document.getElementById("if_index").value = index;
  document.getElementById("PortId").innerHTML=obj.cells[0].innerText;
  if(obj.cells[2].innerText != "--")
  {
  	document.getElementById("VlanPair").value=obj.cells[2].innerText;
  }
  else
  {
    document.getElementById("VlanPair").value='';
  }
  document.getElementById("TableUrlInfo").style.display = "block";
}

function addline(index)
{
	var newline;
	var mode= getValue('Mode'+index);
	newline = document.getElementById('Special_Table').insertRow(-1);
	newline.nowrap = true;
	newline.vAlign = "top";
	newline.align = "center";
	newline.onclick = function() {ModifyInstance(this, index)};
	newline.setAttribute("class","white");
	newline.setAttribute("className","white");
	newline.insertCell(-1).innerHTML = convertDisplay(index, 0);
	newline.insertCell(-1).innerHTML = convertDisplay(mode,1);
	newline.insertCell(-1).innerHTML = (mode==0)?"--":convertDisplay(index, 2);
}

function showTable()
{
	//var num = getValue('if_instnum');
	var num = vlan_mapping_interface.length;
	var port = vlan_mapping_interface;

	if (num!=0) {
		for (var i=0; i<num; i++) {
			if (port[i] == "SSID_DISABLE") {
				continue;
			}
			addline(i);
		}
	}
	else {
	}
}

/********************************************************************
**          on document load
********************************************************************/
function on_init()
{
	showTable();
}

function checkVLANRange(vlan)
{
	var num = reservedVlanA.length;
	for(var i = 0; i<num; i++){
		if(vlan == reservedVlanA[i])
			return false;
	}
	if(sji_checkdigitrange(vlan, otherVlanStart, otherVlanEnd) == true)
		return false;
	//return vlan==parseInt(vlan)&&0<vlan&&vlan<4095;
	return true;
}

function OnChooseDeviceType(Select)
{
   var Mode = document.getElementById("Frm_Mode").value;

   if (Mode == "0")
       document.getElementById("BindVlanRow").style.display = 'none';        
   else if (Mode == "1")
       document.getElementById("BindVlanRow").style.display = '';
}

//用户点击了取消按钮后的代码逻辑
function OnCancelButtonClick()
{
    document.getElementById("TableUrlInfo").style.display = "none";
    return false;
}

function OnApplyButtonClick()
{
	if(1 == document.getElementById("Frm_Mode").value) //vlan bind
	{
		var BindVlan = document.getElementById("VlanPair").value;
		if(false == IsBindBindVlanValid(BindVlan))
		{
			return false;
		}
	}
	
	document.forms[0].submit();
	return true;
}

function IsBindBindVlanValid(BindVlan)
{   
	var LanVlanWanVlanList = BindVlan.split(",");
	var LanVlan;
	var WanVlan;
	var TempList;
	
	if ( LanVlanWanVlanList.length > 4)
	{
			alert("Max support four VLAN pairs");
			return false;
	}

	for (var i = 0; i < LanVlanWanVlanList.length; i++)
	{
		TempList = LanVlanWanVlanList[i].split("/");
		
		/* 检验是否满足a/b格式 */
		if (TempList.length != 2)
		{
			alert(BindVlan+"format invalid");
			return false;
		}
		
		/* 检验a，b是否为数字 */
		if ((isNaN(parseInt(TempList[0]))) || (isNaN(parseInt(TempList[1]))))
		{
			alert(BindVlan+"format invalid");
			return false;
		}
		
		/* 检验lan口的vlan是否合法, 如果需要更加精确的检查，调用checkVLANRange */
		if (!(parseInt(TempList[0]) >= 1 && parseInt(TempList[0]) <= 4095))
		{
			alert(BindVlan+" Vlan\""+parseInt(TempList[0])+"\"invalid");
			return false;
		}
		
		if (!(parseInt(TempList[1]) >= 1 && parseInt(TempList[1]) <= 4095))
		{
			alert(BindVlan+" Vlan\""+parseInt(TempList[1])+"\"invalid");
			return false;
		}

		LanVlan = "Frm_VLAN"+i+"a";
		WanVlan = "Frm_VLAN"+i+"b";

		document.getElementById(LanVlan).value = TempList[0];
		document.getElementById(WanVlan).value = TempList[1];	
	}

	return true;
}
</script>

</head>

<!-------------------------------------------------------------------------------------->
<!--主页代码-->
<body onLoad="on_init();">
<div class="intro_main ">
	<p class="intro_title">Binding <%multilang(LANG_CONFIGURATION);%></p>
	<p class="intro_content">You can undertake the operation of the VLAN binding, the value of the VLAN Settings in m1 / n1 VLAN on way. m1 represents the user side of the VLAN, n1 represents the interface of the VLAN, multiple sets of VLAN in separated by commas.</p>
</div>
<br/>
        
        <!--TODO:在这里加入你的具体页面展现-->
        <div class="data_common data_vertical">
        <table id="Special_Table">
          <tr>
            <th width="10%" align="center"><%multilang(LANG_PORT);%></th>
            <th width="15%" align="center">Binding Mode</th>
            <th width="75%" align="center">VLAN Binding Coniguration</th>
          </tr>
		</table>
	</div>
        
        <!--Apply和Cancel按钮-->
        <div id="TableUrlInfo" style="display:none">
        <form id="vmap" action=/boaform/formVlanMapping method=POST name=vmap>
        <div class="data_common data_common_notitle">
          <table>
            <tbody>
            	<tr class="trTabConfigure">
              <th width="25%" class="table1_left"><%multilang(LANG_PORT);%>
              </th><td class="table1_right"><div id="PortId"></div></td>
              </tr>
            
          </tbody></table>
          <table >
            <tbody><tr class="trTabConfigure">
              <th width="25%" class="table1_left">Binding Mode</th>
              <td class="table1_right"><select name="Frm_Mode" id="Frm_Mode" onchange="OnChooseDeviceType(this);">
                  <option value="1">VLAN binding</option>
                  <option value="0">Port binding</option>
                </select></td>
            </tr>
          </tbody></table>
          <div id="BindVlanRow">
            <table >
              <tbody><tr class="trTabConfigure">
                <th width="25%" class="table1_left">Binding VLAN</th>
                <td class="table1_right"><input type="text" id="VlanPair" style="width:300px" maxlength="255"></td>
              </tr>
            </tbody></table>
          </div>
          <table id="ConfigPanelButtons" width="100%" cellspacing="1" class="table1_button">
            <tbody>
            <tr  align="center">
              <td class="table1_submit" style="padding-left: 5px"><input type="hidden" value="0" name="entryidx">
				<input type='hidden' id="Frm_Mode"   name="Frm_Mode"   type="text" value="">
				<input type='hidden' id="Frm_VLAN0a" name="Frm_VLAN0a" type="text" value="">
				<input type='hidden' id="Frm_VLAN0b" name="Frm_VLAN0b" type="text" value="">
				<input type='hidden' id="Frm_VLAN1a" name="Frm_VLAN1a" type="text" value="">
				<input type='hidden' id="Frm_VLAN1b" name="Frm_VLAN1b" type="text" value="">
				<input type='hidden' id="Frm_VLAN2a" name="Frm_VLAN2a" type="text" value="">
				<input type='hidden' id="Frm_VLAN2b" name="Frm_VLAN2b" type="text" value="">
				<input type='hidden' id="Frm_VLAN3a" name="Frm_VLAN3a" type="text" value="">
				<input type='hidden' id="Frm_VLAN3b" name="Frm_VLAN3b" type="text" value="">
				<input type='hidden' name=if_index ID=if_index value=''>
				<input type="hidden" name="submit-url" value="/net_vlan_mapping.asp">
				<button class="btnsaveup" name="save" onclick="javascript:return OnApplyButtonClick();">Apply</button>
							 &nbsp;&nbsp;
				<button class="BtnCnl" name="save" onclick="javascript:OnCancelButtonClick();">Cancel</button>
            </tr>
          </tbody>
          </table>
          </div>
          </form>
          	<input type='hidden' name=if_instnum ID=if_instnum value=14>
	 		<input type='hidden' name=Mode0   ID=Mode0 value='0'>
	 		<input type='hidden' name=VLAN0   ID=VLAN0 value=''>
	 		<input type='hidden' name=Mode1   ID=Mode1 value='0'>
	 		<input type='hidden' name=VLAN1   ID=VLAN1 value=''>
	 		<input type='hidden' name=Mode2   ID=Mode2 value='0'>
	 		<input type='hidden' name=VLAN2   ID=VLAN2 value=''>
	 		<input type='hidden' name=Mode3   ID=Mode3 value='0'>
	 		<input type='hidden' name=VLAN3   ID=VLAN3 value=''>
	 		<input type='hidden' name=Mode4   ID=Mode4 value='0'>
	 		<input type='hidden' name=VLAN4   ID=VLAN4 value=''>
	 		<input type='hidden' name=Mode5   ID=Mode5 value='0'>
	 		<input type='hidden' name=VLAN5   ID=VLAN5 value=''>
	 		<input type='hidden' name=Mode6   ID=Mode6 value='0'>
	 		<input type='hidden' name=VLAN6   ID=VLAN6 value=''>
	 		<input type='hidden' name=Mode7   ID=Mode7 value='0'>
	 		<input type='hidden' name=VLAN7   ID=VLAN7 value=''>
	 		<input type='hidden' name=Mode8   ID=Mode8 value='0'>
	 		<input type='hidden' name=VLAN8   ID=VLAN8 value=''>
	 		<input type='hidden' name=Mode9   ID=Mode9 value='0'>
	 		<input type='hidden' name=VLAN9   ID=VLAN9 value=''>
	 		<input type='hidden' name=Mode10   ID=Mode10 value='0'>
	 		<input type='hidden' name=VLAN10   ID=VLAN10 value=''>
	 		<input type='hidden' name=Mode11   ID=Mode11 value='0'>
	 		<input type='hidden' name=VLAN11   ID=VLAN11 value=''>
	 		<input type='hidden' name=Mode12   ID=Mode12 value='0'>
	 		<input type='hidden' name=VLAN12   ID=VLAN12 value=''>
	 		<input type='hidden' name=Mode13   ID=Mode13 value='0'>
	 		<input type='hidden' name=VLAN13   ID=VLAN13 value=''>
	 		<script>
	 		<% initPagePBind(); %>
	 		</script>
	 		
        </div>
      </td>
      </tr>
			</tbody>
			</table>
</body>
<%addHttpNoCache();%>
</html>

