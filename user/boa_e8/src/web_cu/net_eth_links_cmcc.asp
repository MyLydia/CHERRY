<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<!--系统默认模板-->
<html>
<HEAD>
<TITLE>宽带设置</TITLE>
<META http-equiv=pragma content=no-cache>
<META http-equiv=cache-control content="no-cache, must-revalidate">
<META http-equiv=Content-Language content=zh-cn>
<META http-equiv=Content-Type content="text/html; charset=gb2312">
<!--系统公共css-->
<STYLE type=text/css>
@import url(/style/default.css);
</STYLE>
<style>
TABLE{width:100%;}
TR{height:16px;}
SELECT {width:150px;}
.addwan{padding-left: 180px;}
.addwan input{
	color: #fff;
    border: 1px solid #888888;
    text-decoration: none;
    padding: 3px 10px;
    margin-top: 20px;
    display: inline-block;
    background: 0 none;
}
</style>
<!-- <META content="MSHTML 6.00.6000.16809" name=GENERATOR> -->
</HEAD>
<BODY style="TEXT-ALIGN: center" vLink=#000000 aLink=#000000 link=#000000 onload="on_init()" marginheight="0" marginwidth="0">
<TABLE cellSpacing=0 cellPadding=0 align=center border=0 class="major">
<TBODY>
<TR>
<TD class="header">
  <TABLE cellSpacing=0 cellPadding=0 border=0 class="tbl_nav">
    <TBODY>
      <TR>
        <!-- <TD>&nbsp;</TD> -->
        <TD vAlign=top align=right><TABLE id=table8 cellSpacing=0 cellPadding=0 border=0>
            <TBODY>
              <TR>
             
                  <INPUT id=Selected_Menu type=hidden value="网络->宽带设置" name=Selected_Menu> </TD>
              </TR>
            </TBODY>
          </TABLE></TD>
      </TR>
    </TBODY>
  </TABLE>
    </TD>
    </TR>
  <TR>
  <SCRIPT language="javascript" src="common.js"></SCRIPT>
  <script language="javascript" src="jquery-3.2.1.min.js"></script>
<script type="text/javascript" src="base64_code.js"></script>
    <TD class="content"><SCRIPT language=JavaScript type=text/javascript>

var doubleclick = 0;
var lkmodes = new Array("Bridge", "Route");

var dlmodes = new Array("自动拨号", "按需拨号", "手动拨号");
var md802ps = new Array("(无)", "0", "1", "2", "3", "4", "5", "6", "7");
<% initPageEth2(); %>
<% initVlanRange(); %>
var opts = new Array(new Array("lkmode", lkmodes), 
	new Array("applicationtype", apmodes),
	new Array("pppCtype", dlmodes), new Array("vprio", md802ps));

var curlink = null;
var g_dnsMode;
var g_dnsv6Mode;
var cgi = new Object();
var links = new Array();
var lan_interface_num = 14;
var wlan_interface_change = <%checkWrite("wlan_interface_change") %>;
var ssid2_enable = "<% checkWrite("ssid2_enable"); %>";
with(links){<% initPageEth(); %>}

	var vArrayStr ="";
	var vEntryIndex = "";
	for(var k in links)
	{
		var lk = links[k];
		if (k == 0) {
			vArrayStr = lk.name;
			vEntryIndex = k;
		}
		else {	
			vArrayStr = vArrayStr + "," + lk.name;
			//vEntryIndex = vEntryIndex + "," + k;
			vEntryIndex = vEntryIndex.concat(k);			
		}		
	}
	vArrayStr = vArrayStr + ",";
	vEntryIndex = vEntryIndex + ",";
		
	var nEntryNum = k; 
	var vEntryName = vArrayStr.split(','); 
//done	
	
    var ssidShowNum = 1;
	ssidShowNum = 2;
   	var vCurrentDHCPv6 = "N/A";
	var vBindStatus = "No,No,No,No,No,No,No,No,No,No,No,No,No,No,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1";
	var ppp_flag = 2;
	var manual_flag = 2;
	var vcurConnect = "N/A";
	if(vcurConnect == "Connect_Keep_Alive")
		ppp_flag = 0;
	else if(vcurConnect == "Connect_Manually")
		ppp_flag = 1;	
	vcurConnect = "N/A";
	if(vcurConnect == "connect")
		manual_flag = 0;
	else if((vcurConnect == "disconnect"))
		manual_flag = 1;
	

	var CycleV = "1,2,3,";
	var IFIdxArray = CycleV.split(',');
	var CycleV = "No,";
	var PPPBiArray = CycleV.split(',');

	var IFIdxStore = "1"

	var pppUsrAccess = '|Subscriber,';
	var pppUsrAccessArr = pppUsrAccess.split(",");
	var pppPwdAccess = '|Subscriber,';
	var pppPwdAccessArr = pppPwdAccess.split(",");
	var WanPPP = new Array(null);
	var WanIP = new Array(null);

	var ipv6enable = new Array(new ipv6mode("InternetGatewayDevice.DeviceInfo.X_CT-COM_IPProtocolVersion","3"),null);
	var ipv6version = ipv6enable[0].mode;
	var Wan = Array();
	for (i = 0; i < WanIP.length-1; i++)
	{
		Wan[i] = WanIP[i];
	}
	for (j = 0; j < WanPPP.length-1; j++,i++)
	{
		Wan[i] = WanPPP[j];
	}

	var i = 0;
	var AddFlag = false;
	var SelWanIndex = 0;
	var tr069Configurable = <% getInfo("cwmp_conf"); %>;

	var msg = new Array(6);
	msg[0] = "操作成功！";
	msg[1] = "修改失败,一条PVC下只能创建8条Interface！";
	msg[2] = "修改失败,PVC已满,只能创建8条PVC！";
	msg[3] = "创建失败,此PVC已经存在8条Interface！";
	msg[4] = "创建失败,PVC已满,只能创建8条PVC！";
	msg[5] = "删除错误, Interface不存在！";

	var oldIpVer;
	var UsernameOpenFlag = "1";
	var PasswordOpenFlag = "1";
	var VLANIDOpenFlag = "1";
	if(UsernameOpenFlag == "0")
		lockObj('pppUserName', true);
	if(PasswordOpenFlag == "0")
		lockObj('pppPassword', true);
	if(VLANIDOpenFlag == "0")
		lockObj('vlan', true);

	function RefreshPage()
	{
			location.href = document.location.href;
	}
	
	function isNameUnsafeEx(compareChar)
	{
	   if ( compareChar.charCodeAt(0) > 32
			&& compareChar.charCodeAt(0) < 127)
		  return false; // found no unsafe chars, return false
	   else
		  return true;
	}
	// Check if a name valid
	function isValidNameEx(name) {
	   var i = 0;

	   for ( i = 0; i < name.length; i++ ) {
		  if ( isNameUnsafeEx(name.charAt(i)) == true )
			 return false;
	   }

	   return true;
	}
	
	function setTextContent (sId, sValue)
	{
		var item;
		if (null == (item = getElById(sId)))
		{
				alert(sId + " is not existed" );
				return false;
		}

		item.value = sValue;
		return true;
	}

	function setRadioContent(sId, sValue)
	{
		var item;
		if (null == (item = getElById(sId)))
		{
			alert(sId + " is not existed" );
			return false;
		}

		for (i=0; i<item.length; i++)
		{
			if (item[i].value == sValue)
			{
				item[i].checked = true;
				return true;
			}
		}
		alert("the option which value is " + sValue + " is not existed in " + sId);
		return false;
	}

	function setSelectContent(sId, sValue)
	{
			var item;
			if (null == (item = getElById(sId)))
			{
					alert(sId + " is not existed" );
					return false;
			}

			for (var i = 0; i < item.options.length; i++)
			{
			if (item.options[i].value == sValue)
					{

					item.selectedIndex = i;
					return true;
			}
		}
		alert("the option which value is " + sValue + " is not existed in " + sId);
		return false;
	}


	function setSelectContentByID(sId, id)
	{
		var item;
		if (null == (item = getElById(sId)))
		{
				alert(sId + " is not existed" );
				return false;
		}
		
		item.selectedIndex = id;
		return true;
	}	

	function setCheckContent(sId, value)
	{
			var item;
			item = getElById(sId);
			if (null == (item = getElById(sId)))
			{
					alert(sId + " is not existed" );
					return false;
			}

		if ( value == '1' )

			{

			 item.checked = true;
					// item.value = 1;
		}
			else
			{
			 item.checked = false;
					// item.value = 0;
		}

		return true;
	}



	function setDisable(sId, flag)
	{
			var item;
			if (null == (item = getElById(sId)))
			{
					alert(sId + " is not existed" );
					return false;
			}

		if ( flag == 1 || flag == '1' )
			{
			 item.disabled = true;
		}
			else
			{
			 item.disabled = false;
		}

		return true;
	}


	function getElementById(sId)
	{
		if (document.getElementById)
		{
			return document.getElementById(sId);
		}
		else if (document.all)
		{
			// old IE
			return document.all(sId);
		}
		else if (document.layers)
		{
			// Netscape 4
			return document.layers[sId];
		}
		else
		{
			return null;
		}
	}


	function getElementByName(sId)
	{    // standard
		if (document.getElementsByName)
		{
			var element = document.getElementsByName(sId);

			if (element.length == 0)
			{
				return null;
			}
			else if (element.length == 1)
			{
				return  element[0];
			}
			return element;
		}
	}


	function getElement(sId)
	{
		 var ele = getElementByName(sId);
		 if (ele == null)
		 {
				return getElementById(sId);
		 }
		 return ele;
	}


	function getElById(sId)
	{
		return getElement(sId);
	}

	function setDisplay (sId, sh)
	{
		var status;
		if (sh > 0)
		{
			status = "";
		}
		else
		{
			status = "none";
		}

		getElement(sId).style.display = status;
	}

	function getRadioVal(sId)
	{
		var item;
		if (null == (item = getElById(sId)))
		{
			alert(sId + " is not existed" );
			return -1;
		}
		for (i = 0; i < item.length; i++)
		{
			if (item[i].checked == true)
			{
			   return item[i].value;
			}
		}

		return -1;
	}

	function getSelectVal(sId)
	{
	   return getValue(sId);
	}

	function getValue(sId)
	{
		var item;
		if (null == (item = getElById(sId)))
		{
			alert(sId + " is not existed" );
			return -1;
		}

		return item.value;
	}

	function setCheckContent(sId, value)
	{
		var item;
		item = getElById(sId);
		if (null == (item = getElById(sId)))
		{
			alert(sId + " is not existed" );
			return false;
		}

		if ( value == '1' )
		{
			 item.checked = true;
		}
			else
			{
			 item.checked = false;
		}
		return true;
	}

	function getCheckVal(sId)
	{
		var item;
		if (null == (item = getElById(sId)))
		{
			alert(sId + " is not existed" );
			return -1;
		}
		if (item.checked == true)
		{
			return 1;
		}

		else
		{
			return 0;
		}
	}
	
	function check_vlan_reserved(vlanID)
	{
			var num = reservedVlanA.length;
			for(var i = 0; i<num; i++){
					if(vlanID == reservedVlanA[i])
							return true;
			}

			return false;
	}
	
	function DisplayLocation(Selected_Menu)
	{
		var Menu = Selected_Menu.split("->");
		var mMenu = Menu[0];
		var sMenu = Menu[1];
		var mMenuClass;
		var sMenuClass;
	}
		
		
		
	function isPPPproxybiOn()
	{

		if ( 'none' != getElement('ppp_bi').style.display )
		{
			if ( getCheckVal('cb_enable_pppbi') == '1' )
				return 1;
		}

		return 0;
	}
	function checkDupPPPBi()
	{
		var curIdx = "0";
		var i = 0;
		
		if ( 1 == isPPPproxybiOn() )
		{
			for( i = 0; i < nEntryNum; i++ )
			{
				if ( curIdx == vEntryIndex[i] )
					continue;
				if ( 
					'Yes' == PPPBiArray[i]
					)
					return 1;
			}
		}

		return 0;
	}
	
	function getMaxIFIdx()
	{
		var IFIdxLen = IFIdxArray.length;
		var IFIdxStoreV = 0;
		var i = 0;
		var IFIdxV = 0;
		
		if ( isPlusInteger(IFIdxStore) )
			IFIdxStoreV = parseInt(IFIdxStore);
		
		IFIdxStoreV ++;
		
		for ( i = IFIdxStoreV; i <= 99; i ++ )
		{
			if (!isIdExist(i))
				return i;
		}
		
		for ( i = 1; i < IFIdxStoreV; i ++ )
		{
			if (!isIdExist(i))
				return i;
		}

		return 1; 
	}
	
	function isIdExist(ifIdx)
	{
		var i = 0;
		var IFIdxV = 0;
		var IFIdxLen = IFIdxArray.length;
		
		for ( i = 0; i < IFIdxLen; i ++ )
		{
			IFIdxV = parseInt(IFIdxArray[i]);

			if ( IFIdxV == ifIdx )
				return true;
		}
		
		return false;
	}
	

	function trimString(destStr, cTrim)
	{
		var i;
		var j;
		var retStr = '';
		for (i = 0; i < destStr.length; i++)
		{
			if (destStr.charAt(i) != cTrim)
			{
				retStr += destStr.charAt(i);
			}
		}
		return retStr;
	}


	function ipv6mode(domain, mode)
	{
		this.domain = domain;
		this.mode = mode;
	}

	function LoadFrame()
	{
		$("#enableDisplay *").prop("disabled", false);
		with (getElById('ConfigForm'))
		{
			Wan_Flag.value = "0";
			var wanStatus = "N/A";
			if((0 != parseInt(wanStatus)) && (wanStatus != "N/A"))
			{
				if(99 == parseInt(wanStatus))
				{
					alert(msg[5]);
				}
				else{
					alert(msg[parseInt(wanStatus)]);
				}
				document.ConfigForm.submit();
			}
//alert("CurWan is " + CurWan.length-1);

			oldIpVer = getRadioVal("IpVersion");
			if ((CurWan.length-1) > 0)
			{
				WanModeChange();
				if (serviceList.value == "TR069" || serviceList.value == "VOIP" || serviceList.value == "TR069_VOIP" )
				{
					dhcpv6pdflag.value = "No";
					setDisplay('secBind',0);
					setDisplay('secNat',0);
					clearBindList();
					clearbindwireless();
					
					clearbindwireless5G();
					
				}
				else
				{
					var ipVer = getRadioVal("IpVersion");


					setDisplay('secBind',1);


					if((wanMode.value == "Bridge") || ("IPv6" == ipVer)) setDisplay('secNat',0);
					else setDisplay('secNat',1);
				}
				if(linkMode.value == "linkPPP")
					DialMethodChange();
				VLANModeChg();
				
				WanCurrIFIdx.value = getIFIdxvidDomain(getSelectVal('wanId'));
			}
			else
			{
				onChangeSvrList();
				ServiceListLoad(0);
			}
			var isCYE8SFUSupported="N/A";
			var wanuilimit="N/A";
			if("Yes" == isCYE8SFUSupported && "1" != wanuilimit){
			  btnAddCnt.style.display="none";
			  btnRemoveCnt.style.display="none";
			}
		}
		
		
		//SelWanIndex = 0;
		loadPageByWanID(SelWanIndex);
		isTr069Configurable();
	}

	function on_init()
	{
		setSelectContentByID('wanId', SelWanIndex);
		if(ssid2_enable != 1)
			getElById('enableDisplay2').style.display = "none";
		LoadFrame();
	}
	
	function loadPageByWanID(selWAN)
	{
		var wanConfig = links[selWAN];
		
		//连接名称：
		setTextContent('wanName', wanConfig.name);
		
		//模式：
		if (wanConfig.cmode == 0) {
			setSelectContent('wanMode',"Bridge");
		}
		else 
		{
			setSelectContent('wanMode',"Route");
		}
		WanModeChange();
		
		//启用
		setCheckContent('cb_enblService', wanConfig.enable);	
		
		//承载业务：	
		if (wanConfig.cmode == 0) //Bridge , application list is only INTERNET/OTHER
		{
			if (wanConfig.applicationtype == 1) 
				setSelectContent('serviceList', 'INTERNET');
			else if (wanConfig.applicationtype == 3)
				setSelectContent('serviceList', 'OTHER');
			else if (wanConfig.applicationtype == 8)
				setSelectContent('serviceList', 'IPTV');
		}
		else
		{
			if ( wanConfig.applicationtype == 0) {
				setSelectContentByID('serviceList', 2);	
			}
			else if ( wanConfig.applicationtype == 1) {
				setSelectContentByID('serviceList', 1);	
			}
			else if ( wanConfig.applicationtype == 2){
				setSelectContentByID('serviceList', 0);	
			}
			else if ( wanConfig.applicationtype == 3){
				setSelectContentByID('serviceList', 7);	
			}
			else if ( wanConfig.applicationtype == 4) {
				setSelectContentByID('serviceList', 3);	
			}
			else if ( wanConfig.applicationtype == 5) {
				setSelectContentByID('serviceList', 4);	
			}
			else if ( wanConfig.applicationtype == 6) {
				setSelectContentByID('serviceList', 5);	
			}		
			else if ( wanConfig.applicationtype == 7) {
				setSelectContentByID('serviceList', 6);
			}	
			else if ( wanConfig.applicationtype == 8) {
				setSelectContentByID('serviceList', 8);
			}
		}
		onChangeSvrList();
		
		//桥类型： ?? IP_BRIDGE/PPPoE_Bridge
		if (wanConfig.cmode == 0) 
		{
			if(wanConfig.brmode)
				setSelectContent('bridgeMode', "PPPoE_Bridged");
			else
				setSelectContent('bridgeMode', "IP_Bridged");
		}
		
		//DHCP Server启用：
		if(wanConfig.disableLanDhcp)
			setCheckContent('cb_enabledhcp', 0);
		else
			setCheckContent('cb_enabledhcp', 1);

		//绑定选项：
		//itfGroup  //bit0- LAN 1; bit1- LAN 2; bit2- LAN 3; bit3- LAN 4; bit 4- WLAN ROOT; bit5- WLAN SSID1; ...
		//1,2,4,8,16,32,64
		if (wanConfig.wlanMode == 2) { //Dual Band
			setDisplay('wlan_table_1', 1);
			setDisplay('wlan_table_2', 1);
		}
		else
		{
			setDisplay('wlan_table_1', 1);
			setDisplay('wlan_table_2', 0);
		}		
		setCheckContent('cb_bindlan1', 0);
		setCheckContent('cb_bindlan2', 0);
		setCheckContent('cb_bindlan3', 0);
		setCheckContent('cb_bindlan4', 0);
		setCheckContent('cb_bindwireless1', 0);
		setCheckContent('cb_bindwireless2', 0);
		setCheckContent('cb_bindwirelessac1', 0);
		if (wanConfig.itfGroup != 0) {
			if (wanConfig.itfGroup & (0x1 << 0))
				setCheckContent('cb_bindlan1', 1);
			if (wanConfig.itfGroup & (0x1 << 1))
				setCheckContent('cb_bindlan2', 1);
			if (wanConfig.itfGroup & (0x1 << 2))
				setCheckContent('cb_bindlan3', 1);
			if (wanConfig.itfGroup & (0x1 << 3))
				setCheckContent('cb_bindlan4', 1);
			if (wanConfig.itfGroup & (0x1 << 4))
				setCheckContent('cb_bindwireless1', 1);
			if (wanConfig.itfGroup & (0x1 << 5))
				setCheckContent('cb_bindwireless2', 1);
			if (wanConfig.itfGroup & (0x1 << 9))
				setCheckContent('cb_bindwirelessac1', 1);
		}	
		
		//链接方式	 
		if ( wanConfig.cmode == 2 ){  //cmode:0- bridge; (1-2)- Route; 2- PPPoE
			setSelectContent('linkMode',"linkPPP");
			//linkMode.value = "linkPPP";
			linkModeSelect();
		} 
		else if ( wanConfig.cmode == 1 ){
			setSelectContent('linkMode',"linkIP");
			//linkMode.value = "linkIP";
			linkModeSelect();
			if (wanConfig.ipDhcp == 0) //static
			{
				setRadioContent("IpMode", "Static");
			}
			else if (wanConfig.ipDhcp == 1) //dhcp
			{
				setRadioContent("IpMode", "DHCP");
			}
		} 
		else //bridge
		{
		}
		
		//IP协议版本：
		if ( wanConfig.IpProtocolType == 1) //IPV4
		{
			setRadioContent('IpVersion', "IPv4" );
		}
		else if ( wanConfig.IpProtocolType == 2 ) //IPV6
		{
			setRadioContent('IpVersion','IPv6' );
		}
		else 
		{
			setRadioContent('IpVersion','IPv4/IPv6' );
		}
		IpVersionChange();
		MTUDispChange();
		
		//VLAN模式：
		if( wanConfig.vlan == 0) //untag
			setSelectContent('VLANMode', 'UNTAG');
		else if (wanConfig.vlan == 1 ) //TAG
		{
			setSelectContent('VLANMode', 'TAG');
			//VLAN ID[1-4094]：
			setTextContent('vlan', wanConfig.vid);			
		}
		else //transparent
			setSelectContent('VLANMode', 'TRANSPARENT');
		VLANModeChg();		
				
		//802.1p[0-7]：
		if (wanConfig.vprio == 0)
			setCheckContent('cb_8021P', 0);
		else {
			setCheckContent('cb_8021P', 1);
			}
		Enable8021PClick();
		
		if (wanConfig.vprio != 0)
			setTextContent('v8021P', wanConfig.vprio-1);
		//组播VLAN ID[1-4094]：
		setTextContent('MulticastVID', wanConfig.mcastVid);
		
		//MTU[128-1492]：
		setTextContent('MTU', wanConfig.mtu);
		//使能NAT：
		setCheckContent('cb_nat', wanConfig.napt);

		//PPPoE撥號模式：
		if( wanConfig.pppCtype == 0) //auto
		{
			setSelectContent('DialMethod', 'Auto');
		}
		else if (wanConfig.pppCtype == 1 ) //on demand
		{
			setTextContent('pppTimeOut', wanConfig.pppIdleTime);
			setSelectContent('DialMethod', 'OnDemand');
		}
		else //manual 
		{
			setSelectContent('DialMethod', 'Manual');
		}
		DialMethodChange();
		
		//IP 地址：	
		setTextContent('wanIpAddress', wanConfig.ipAddr);
		
		//子网掩码：
		setTextContent('wanSubnetMask', wanConfig.netMask);
		
		//缺省网关：
		setTextContent('defaultGateway', wanConfig.remoteIpAddr);
		
		//首选DNS服务器：
		setTextContent('dnsPrimary', wanConfig.v4dns1);
		
		//备用DNS服务器：
		setTextContent('dnsSecondary', wanConfig.v4dns2);
		
		//IPv6地址:
		setTextContent('IdIpv6Addr', wanConfig.Ipv6Addr);
		setTextContent('IdIpv6PrefixLen', wanConfig.Ipv6PrefixLen);
		//IPv6默认网关:(IPv6默认网关不填内容，则自动获取 to-Do) 
		setTextContent('IdIpv6Gateway', wanConfig.Ipv6Gateway);
		
		//IPv6首选DNS服务器:
		setTextContent('IdIpv6Dns1', wanConfig.Ipv6Dns1);
		
		//IPv6备用DNS服务器:
		setTextContent('IdIpv6Dns2', wanConfig.Ipv6Dns2);
		
		//用户名：
		//alert( "PPPoE user=" + decode64(wanConfig.encodePppUserName));
		setTextContent('pppUserName', decode64(wanConfig.encodePppUserName));
		
		//密码：		
		setTextContent('pppPassword', wanConfig.pppPassword);

		//服务名称
		setTextContent('pppServiceName', wanConfig.pppServiceName);
		
		//PPPoE路由桥混合模式启用：
		setCheckContent('cb_enable_pppbi', wanConfig.brmode);
		
		//IPv6 WAN信息获取方式:
		//AddrMode Bitmap, bit0: Slaac, bit1: Static, bit2: DS-Lite , bit3: 6rd, bit4: DHCP Clien
		if (wanConfig.AddrMode == 1)
			setSelectContent('IdIpv6AddrType', "SLAAC");
		else if (wanConfig.AddrMode == 2) //Static
			setSelectContent('IdIpv6AddrType', "Static");
		else if (wanConfig.AddrMode == 16) //DHCP
			setSelectContent('IdIpv6AddrType', "DHCP");

		if (wanConfig.IpProtocolType == 2 || wanConfig.IpProtocolType == 3)
			OnIPv6Changed();
		
		//PD使能：
		setCheckContent('cb_enabledpd',wanConfig.iapd);
		cb_pdEnableChange();
		
		//前缀模式： AUTO/Manul  to-Do , auto only right now
		setRadioContent('pdmode', 'Yes');
		pdmodeChange();
		
		//前缀地址： (Manual)
		//首选寿命： (Manual)
		//有效寿命： (Manual)
		
		
		//DS-Lite启用：
		setCheckContent('cb_enabledslite', wanConfig.dslite_enable);
		cb_enabledsliteChange();
		
		//DS-Lite模式：
		setRadioContent('dslitemode', wanConfig.dslite_aftr_mode);
		dslitemodeChange();
		setTextContent('dsliteaddress', wanConfig.dslite_aftr_hostname);
				
		//使能DHCP透传： 

		
	}

	function IpVersionChange()
	{
		with (getElById('ConfigForm'))
		{
			var ipVer = getRadioVal("IpVersion");
			var ConnType = getSelectVal('wanMode');
			var Serverlist = getSelectVal('serviceList');
			if (ConnType != 'Route')
			{
				setDisplay('divIpVersion', 1);
				setDisplay('secIPv6Div', 0);
				return;
			}
			setDisplay('divIpVersion', 1);
			setDisplay('secIPv6Div', 1);
			if ("IPv4" == ipVer)
			{
				if (Serverlist == "TR069"  || Serverlist == "VOIP" || Serverlist == "TR069_VOIP" )
				{
					setDisplay('secNat', 0);
					nat.value = "Disabled";
				}
				else
				{
					setDisplay('secNat', 1);
					if ( oldIpVer != ipVer )
					{
						nat.value = "Enable";
						setCheckContent('cb_nat', 1);
					}
				}
				if ('linkIP' == getSelectVal('linkMode'))
				{
					setDisplay('secDhcp', 1);
					setDisplay('secStatic', 1);
					setDisplay('secPppoeItems', 0);
					if (SelWanIndex != -1)
					{
/* iulian marked 					
						if ((Wan[SelWanIndex].addrType == 'DHCP') || (Wan[SelWanIndex].wanConn == "PPPCon"))
						{
							IpMode[0].checked = true;
						}
						else
						{
							IpMode[1].checked = true;
						}
*/						
					}
				}
				else
				{
					setDisplay('secDhcp', 0);
					setDisplay('secStatic', 0);
					setDisplay('secPppoeItems', 1);
				}
				setDisplay('secPppoe', 0);
				setDisplay('secPppoa', 0);
				setDisplay('secIpoa', 0);
				if(IpMode[1].checked && ("linkIP" == getSelectVal('linkMode')))
				{
					setDisplay('secStaticItems', 1);
				}
				else
				{
					setDisplay('secStaticItems', 0);
				}
				setDisplay('TrIpv6AddrType', 0);
				setDisplay('TrIpv6Addr', 0);
				setDisplay('TrIpv6Dns1', 0);
				setDisplay('TrIpv6Dns2', 0);
				setDisplay('TrIpv6Gateway', 0);
				setDisplay('TrIpv6GatewayInfo', 0);
			}
			else if ("IPv6" == ipVer)
			{
				setDisplay('secNat', 0);
				nat.value = "Disabled";
				setDisplay('secDhcp', 0);
				setDisplay('secStatic', 0);
				setDisplay('secPppoe', 0);
				setDisplay('secPppoa', 0);
				setDisplay('secIpoa', 0);
				setDisplay('secStaticItems', 0);
				setDisplay('TrIpv6AddrType', 1);
				var linkstr = getSelectVal('linkMode');
				if(linkstr == "linkIP")
					WriteIPv6List(1);
				else
					WriteIPv6List(0);
			}
			else
			{
				if (Serverlist == "TR069"  || Serverlist == "VOIP" || Serverlist == "TR069_VOIP")
				{
					setDisplay('secNat', 0);
					nat.value = "Disabled";
				}
				else
				{
					setDisplay('secNat', 1);
					if ( oldIpVer != ipVer )
					{
						nat.value = "Enable";
						setCheckContent('cb_nat', 1);
					}
				}
				if ('linkIP' == getSelectVal('linkMode'))
				{
					setDisplay('secDhcp', 1);
					setDisplay('secStatic', 1);
					setDisplay('secPppoeItems', 0);
					if (SelWanIndex != -1)
					{
/*  iulian				
						if ((Wan[SelWanIndex].addrType == 'DHCP') || (Wan[SelWanIndex].wanConn == "PPPCon"))
						{
							IpMode[0].checked = true;
						}
						else
						{
							IpMode[1].checked = true;
						}
*/						
					}
				}
				else
				{
					setDisplay('secDhcp', 0);
					setDisplay('secStatic', 0);
					setDisplay('secPppoeItems', 1);
				}
					setDisplay('secPppoe', 0);
					setDisplay('secPppoa', 0);
					setDisplay('secIpoa', 0);
					if (('linkIP' == getSelectVal('linkMode')) && IpMode[1].checked)
					{
						setDisplay('secStaticItems', 1);
					}
					else
					{
						setDisplay('secStaticItems', 0);
					}
					setDisplay('TrIpv6AddrType', 1);
					if('linkIP' == getSelectVal('linkMode'))
					{
						if(IpMode[0].checked)
						{
							WriteIPv6List(0);
						}
						else if(IpMode[1].checked)
							WriteIPv6List(2);
						else
							WriteIPv6List(0);
					}
					else
						WriteIPv6List(0);
				}
				oldIpVer = ipVer;
				
				dsliteShow();
				pdEnableShow();
				ppp_dialMethodChg();
		}
	}
	
	var changeflag = 1;
	function onChangeSvrList()
	{
		with (getElById('ConfigForm'))
		{
			if ((serviceList.value == 0) && (IpMode[2].checked == true) && (wanMode.value != "Bridge"))
			{
				changeflag = 0;
				secManualDial.style.display = "none";
				secIdleTime.style.display = "none";
			}
			else if((serviceList.value != 0) && (IpMode[2].checked == true) && (wanMode.value != "Bridge"))
			{
				if(changeflag == 0)
				{
					addOption(DialMethod,1,"有流量时自动连接");
					addOption(DialMethod,'Manual',"手动拨号");
					changeflag = 1;
				}
			}
			if (serviceList.value == "TR069"   || serviceList.value == "VOIP" || serviceList.value == "TR069_VOIP" )
			{
				dhcpv6pdflag.value = "No";
				cb_nat.checked = false;
				nat.value = "Disabled";
				setDisplay('secBind',0);
				setDisplay('secNat',0);
				clearBindList();
				clearbindwireless();
				
				clearbindwireless5G();
				
			}
			else
			{
				dhcpv6pdflag.value = "Yes";
				cb_nat.checked = true;
				nat.value = "Enable";


				setDisplay('secBind',1);


				if(wanMode.value == "Bridge")
				{
					setDisplay('secNat',0);
					nat.value = "Disabled";
				}
				else
				{
					setDisplay('secNat',1);
				}
			}
			if (AddFlag == true)
			{
				if (serviceList.value == "OTHER" && wanMode.value == "Bridge")
				{
					cb_dhcprelay.checked = true;
				}
				else
				{
					cb_dhcprelay.checked = false;
				}
			}
			IpVersionChange();
			MTUDispChange();
			MultiVIDDispChange();
			dsliteShow();
			pdEnableShow();
			dhcpEnableShow();
			pppoeProxyShow();
			ppp_dialMethodChg();
			isTr069Configurable();
		}
	}
	
	function onSelectSvrList()
	{
		pdDefaultSel = 1;
		enabledhcpSel = 1;
		onChangeSvrList();
		with (getElById('ConfigForm'))
		{
			if (serviceList.value == "OTHER" && wanMode.value == "Bridge")
			{
				cb_dhcprelay.checked = true;
			}
			else
			{
				cb_dhcprelay.checked = false;
			}
		}
	}
	
	function DialMethodChange()
	{
		with (getElById('ConfigForm'))
		{	
			if (DialMethod.value == "Auto" ) //自動模式
			{
				setDisplay('secIdleTime',0);
				setDisplay('secManualDial',0);		
			}
			else if (DialMethod.value == "Manual") //手動模式 
			{
				setDisplay('secIdleTime',0);
				setDisplay('secManualDial',1);
			}
			else // on-demand 模式 
			{
				setDisplay('secIdleTime',1);
				setDisplay('secManualDial',0);
			}
		}
	}
	
	function cb_enblServiceChange()
	{
		if(document.ConfigForm.cb_enblService.checked)
			document.ConfigForm.WanActive.value = "Yes";
		else
			document.ConfigForm.WanActive.value = "No";
	}
	
	function clearBindList()
	{
		for (var i = 1; i <= 4; i++)
		{
			document.getElementById("secLan" + i).disabled = false;
			document.getElementById("cb_bindlan" + i).checked = false;
		}
	}
	
	function clearbindwireless()
	{
		for (var i = 1; i <= ssidShowNum; i++)
		{
			document.getElementById("secWireless" + i).disabled = false;
			document.getElementById("cb_bindwireless" + i).checked = false;
		}
	}
	
	function clearbindwireless5G()
	{
		document.getElementById("secWirelessac1").disabled = false;
		document.getElementById("cb_bindwirelessac1").checked = false;
	}
	
	function linkModeSelect()
	{
		with (getElById('ConfigForm'))
		{
			pdDefaultSel = 1;
			isNeedChange = 1;
			var ipVer = getRadioVal("IpVersion");
			if (getSelectVal('linkMode') == 'linkIP')
			{
				if("IPv6" == ipVer)
					WriteIPv6List(1);
				else if("IPv4/IPv6" == ipVer)
				{
					if(IpMode[0].checked)
						WriteIPv6List(0);
					else if(IpMode[1].checked)
						WriteIPv6List(2);
					else
						WriteIPv6List(0);
				}
				setDisplay("secDhcp", 1);
				setDisplay('secStatic',1);
				
/*
				if (SelWanIndex != -1)
				{
				}
				else
				{
					IpMode[0].checked = true;
				}*/
				IpMode[0].checked = true;
			}
			else
			{
				if("IPv4" != ipVer)
					WriteIPv6List(0);
				setDisplay("secDhcp", 0);
				setDisplay('secStatic',0);
				IpMode[2].checked = true;
				DialMethodChange();
			}
			setDisplay('secPppoe',0);
			IpModeChange();
			IpVersionChange();
			MTUDispChange();
			dsliteShow();
			pdEnableShow();
			dhcpEnableShow();
			pppoeProxyShow();
			ppp_dialMethodChg();
		}
	}

	var isWanModeChg = -1;
	var isAddBtnClick = 0;
	
	function ServiceListLoad(isBridge)
	{
		var bridgeArray = new Array('INTERNET', 'OTHER', 'IPTV');
		var i = 0;
		var status = 'TR069_VOIP_INTERNET';
		var isSel = 0;
		
		//var routeArray = new Array("TR069_INTERNET", "INTERNET", "TR069", "Other", "VOIP", "TR069_VOIP", "VOIP_INTERNET", "TR069_VOIP_INTERNET");
		var routeArray = new Array('TR069', 'INTERNET', 'TR069_INTERNET', 'VOIP', 'TR069_VOIP', 'VOIP_INTERNET', 'TR069_VOIP_INTERNET', 'OTHER', 'IPTV');

		with ( getElById('serviceList') )
		{
			options.length=0;

			if ( 1 == isBridge )
			{
				for( i=0; i< bridgeArray.length; i++)
				{
					var opt = new Option(bridgeArray[i], bridgeArray[i]);
					if ( status == opt.value )
					{
						opt.selected = true;
						isSel = i;
					}
					options.add ( opt );
				}
				options[isSel].setAttribute('selected', 'true');
			}
			else
			{
				for( i=0; i< routeArray.length; i++)
				{
					var opt = new Option(routeArray[i], routeArray[i]);
					if ( status == opt.value )
					{
						opt.selected = true;
						isSel = i;
					}
					options.add ( opt );
				}
				options[isSel].setAttribute('selected', 'true');
			}
			
			if ( -1 == isWanModeChg )
				isWanModeChg = isBridge;
			else
			{
				if ( 	isWanModeChg != isBridge )
				{
					isWanModeChg = isBridge;
					onSelectSvrList();
				}
			}
		}
	}

	function WanModeChange()
	{
		with (getElById('ConfigForm'))
		{
			if (wanMode.value == "Route")
			{
				ServiceListLoad(0);
				setDisplay('secIpMode',1);
				setDisplay('secRouteItems',1);
				setDisplay('divLink', 1);
				setDisplay('secDhcp',1);
				setDisplay('secStatic',1);
				setDisplay('secPppoe',1);
				setDisplay('secbridgeDhcprelay',0);
				setDisplay('secBridgeType',0);
			
				if (serviceList.value == "TR069" || serviceList.value == "VOIP" || serviceList.value == "TR069_VOIP")
				{
					setDisplay('secNat',0);
				}
				else
				{
					setDisplay('secNat',1);
				}
				setDisplay('secIgmp',1);
				IpModeChange();

			}
			else if (wanMode.value == "Bridge")
			{
				ServiceListLoad(1);
				setDisplay('secIpMode',0);
				setDisplay('secRouteItems',0);
				setDisplay('divLink', 0);
				setDisplay('secStaticItems',0);
				setDisplay('secPppoeItems',0);
				setDisplay('secDhcp',0);
				setDisplay('secStatic',0);
				setDisplay('secPppoe',0);
				setDisplay('secBridgeType',1);
				//setDisplay('cb_dhcprelay',1); //iulian disable 
				setDisplay('cb_dhcprelay',0);
				//getElement('secbridgeDhcprelay').style.display = "";
				setDisplay('secbridgeDhcprelay',0);
				setRadioContent("IpVersion", "IPv4");
				setDisplay('secNat',0);
				nat.value = "Disabled";
				setDisplay('secIgmp',0);

			}
			else if (wanMode.value == "multMode")
			{
				setDisplay('secIpMode',1);
				setDisplay('secRouteItems',1);
				setDisplay('secDhcp',0);
				setDisplay('secStatic',0);
				setDisplay('secPppoe',1);
				setDisplay('secbridgeDhcprelay',0);
				IpMode[2].checked = true;
				setDisplay('secNat',1);
				setDisplay('secIgmp',1);
				IpModeChange();
			}
			if (AddFlag == true)
			{
				if (serviceList.value == "OTHER" && wanMode.value == "Bridge")
				{
					//cb_dhcprelay.checked = true; //iulian disable
					cb_dhcprelay.checked = false;
				}
				else
				{
					cb_dhcprelay.checked = false;
				}
			}
			IpVersionChange();
			MTUDispChange();
			MultiVIDDispChange();
			dsliteShow();
			pdEnableShow();
			dhcpEnableShow();
			pppoeProxyShow();
			ppp_dialMethodChg();
		}
	}

	function WanModeSelect()
	{
		isNeedChange = 1;
		WanModeChange();
		linkModeSelect();

		with (getElById('ConfigForm'))
		{
		if (serviceList.value == "OTHER" && wanMode.value == "Bridge")
		{
		//cb_dhcprelay.checked = true; //iulian disable
		cb_dhcprelay.checked = false;
		}
		else
		{
		cb_dhcprelay.checked = false;
		}
			if ( serviceList.value != "TR069"
		&& serviceList.value != "VOIP"
		&& serviceList.value != "TR069_VOIP"
		 && 'Route' == wanMode.value )
			{
				nat.value = "Enable";
				setCheckContent('cb_nat', 1);
			}
		}
	}

	function IpModeChange()
	{
		with (getElById('ConfigForm'))
		{
			var ipVer = getRadioVal("IpVersion");
			if (IpMode[0].checked == true)
			{
				setDisplay('secStaticItems',0);
				setDisplay('secPppoeItems',0);
				document.ConfigForm.ISPTypeValue.value = "0";
				if("IPv4/IPv6" == ipVer){
					if(getSelectVal('linkMode') == 'linkIP')
						WriteIPv6List(0);
				}
					
			}
			else if (IpMode[1].checked == true)
			{
				setDisplay('secStaticItems',1);
				setDisplay('secPppoeItems',0);
				document.ConfigForm.ISPTypeValue.value = "1";
				if("IPv4/IPv6" == ipVer){
					if(getSelectVal('linkMode') == 'linkIP')
						WriteIPv6List(2);
				}
			}
			else if (IpMode[2].checked == true)
			{
				setDisplay('secStaticItems',0);
				setDisplay('secPppoeItems',1);
				document.ConfigForm.ISPTypeValue.value = "2";
			}
			else if (IpMode[3].checked == true)
			{
				setDisplay('secStaticItems',0);
				setDisplay('secPppoeItems',1);
				document.ConfigForm.ISPTypeValue.value = "3";
			}
			else if (IpMode[4].checked == true)
			{
				setDisplay('secStaticItems',1);
				setDisplay('secPppoeItems',0);
				document.ConfigForm.ISPTypeValue.value = "4";
			}
		}
	}
	
	function cb_bindflagChange()
	{
		with (getElById('ConfigForm'))
		{
			if (cb_bindflag.checked == true)
			{
				bindflag.value = "Yes";
				setDisplay('secBind',1);
				if(wanMode.value == "Bridge")
					setDisplay('secbridgeDhcprelay',0);
				else
					setDisplay('secbridgeDhcprelay',0);
				
			}
			else
			{
				bindflag.value = "No";
				setDisplay('secBind',0);
				setDisplay('secbridgeDhcprelay',0);
			}
		}
	}

	function Enable8021PClick()
	{
		document.ConfigForm.v8021P.value = 0;
		if(document.ConfigForm.cb_8021P.checked)
		{
			document.ConfigForm.v8021PClick.value = "Yes";
			setDisplay('v8021P', 1);
		}
		else
		{
			document.ConfigForm.v8021PClick.value = "No";
			setDisplay('v8021P', 0);
		}
	}
	
	function EnableNatClick()
	{
		if(document.ConfigForm.cb_nat.checked)
			document.ConfigForm.nat.value = "Enable";
		else
			document.ConfigForm.nat.value = "Disabled";
	}
	
	function EnableIGMPProxyClick()
	{
		if(document.ConfigForm.cb_enblIgmp.checked)
			document.ConfigForm.enblIgmp.value = "Yes";
		else
			document.ConfigForm.enblIgmp.value = "No";
	}
	
	function EnableDHCPRealy()
	{
		if(document.ConfigForm.cb_dhcprelay.checked)
			document.ConfigForm.dhcprelay.value = "Yes";
		else
			document.ConfigForm.dhcprelay.value = "No";
	}
	
	function isDigit(val) {
		if (val < '0' || val > '9')
			return false;
		return true;
	}
	
	function isDecimalDigit(digit)
	{
		if ( digit == "" )
		{
			return false;
		}
		for ( var i = 0 ; i < digit.length ; i++ )
		{
			if ( !isDigit(digit.charAt(i)) )
			{
				return false;
			}
		}
		return true;
	}
	
	function isUseableIpAddress(address)
	{
		var num = 0;
		var addrParts = address.split('.');
		if (addrParts.length != 4)
		{
			return false;
		}
		if (isDecimalDigit(addrParts[0]) == false)
		{
			return false;
		}
		
		num = parseInt(addrParts[0]);
		if (!(num >= 1 && num <= 223 && num != 127))
		{
			return false;
		}
		
		for (var i = 1; i <= 2; i++)
		{
			if (isDecimalDigit(addrParts[i]) == false)
			{
				return false;
			}
			num = parseInt(addrParts[i]);
			if (!(num >= 0 && num <= 255))
			{
				return false;
			}
		}
		
		if (isDecimalDigit(addrParts[3]) == false)
		{
			return false;
		}
		
		num = parseInt(addrParts[3]);
		if (!(num >= 1 && num <= 254))
		{
			return false;
		}
		return true;
	}


	function CheckForm(type)
	{
		if (type == 0)
		{
			return true;
		}
		
		with (getElById('ConfigForm'))
		{
			if (wanId.length == 0)
			{
			alert("目前没有WAN连接，请点击添加按钮新建一条WAN连接并点击确定按钮以保存配置！");
			return false;
			}
/*
			if ( serviceList.value.indexOf('TR069') >= 0 )
			{
				for(var i=0; i< (CurWan.length-1); i++)
				{
					if ( false == AddFlag && curSetIndex.value == CurWan[i].domain )
						continue;
						
					if ( CurWan[i].WanName.indexOf('TR069') >= 0 )
					{
						alert('只能创建一个TR069 WAN口。');
						return false;
					}
				}
			}
*/
			if ( 'TAG' == VLANMode.value )
			{
				var v = vlan.value;
				if(isPlusInteger(v) == false)
				{
					alert("VLAN ID非法！");
					return false;
				}
				else
				{
					if ((v == "") || (v < 1) || (v > 4094))
					{
						alert("VLAN ID非法！");
						return false;
					}
					
					if (check_vlan_reserved(v))
					{
						alert("VLAN ID非法！请勿使用系统保留VLAN ID!");
						return false;					
					}
				}
			}

			if ( 'TAG' == VLANMode.value )
			{
				var v = v8021P.value;
				if (isPlusInteger(v) == false)
				{
					alert("802.1p非法！");
					return false;
				}
				else
				{
					if ((v == "") || (v < 0) || (v > 7))
					{
						alert("802.1p非法！");
						return false;
					}
				}
			}

			if ( 'none' != getElement('mulvidsec').style.display )
			{
				var v = MulticastVID.value;
				if ( 0 != v.length)
				{
					if (isPlusInteger(v) == false)
					{
						alert("组播VLAN ID非法！");
						return false;
					}
					else
					{
						if ( v < 0 || v > 4094 )
						{
							alert("组播VLAN ID非法！");
							return false;
						}
						
						if ( (v!=0) && (check_vlan_reserved(v)))
						{
							alert("组播VLAN ID非法！请勿使用系统保留VLAN ID!");
							return false;					
						}						
					}
				}
				MulVIDUsed.value = 'Yes';
			}
			else
				MulVIDUsed.value = 'No';

			if ( 'none' != getElement('MTUsec').style.display )
			{
				var v = MTU.value;
				if (isPlusInteger(v) == false)
				{
					alert("MTU非法！");
					return false;
				}
				else
				{
					if (getSelectVal('linkMode') == 'linkPPP')
					{
						if ('IPv4' == getRadioVal('IpVersion'))
						{
							if ((v == '') || ( 0 != v && (v < 128) || (v > 1492)))
							{
								alert("MTU非法，请输入值为128~1492之间的整数！(或0默认)");
								return false;
							}
						}
						else
						{
							if (getCheckVal('cb_enabledslite') == 1){
								if ((v == '') || ( 0 != v && (v < 1320) || (v > 1452)))
								{
									alert("MTU非法，请输入值为1320~1452之间的整数！(或0默认)");
									return false;
								}					
							}else{

								if ((v == '') || ( 0 != v && (v < 1280) || (v > 1492)))
								{
									alert("MTU非法，请输入值为1280~1492之间的整数！(或0默认)");
									return false;
								}					
							}
						}
					}
					else
						{
						if ('IPv4' == getRadioVal('IpVersion'))
						{				
							if ((v == '') || ( 0 != v && (v < 576) || (v > 1500)))
							{
								alert("MTU非法，请输入值为576~1500之间的整数！(或0默认)");
								return false;
							}
						}
						else
						{
							if (getCheckVal('cb_enabledslite') == 1){
								if ((v == '') || ( 0 != v && (v < 1320) || (v > 1460)))
								{
									alert("MTU非法，请输入值为1320~1460之间的整数！(或0默认)");
									return false;
								}				
							}
							else
							{
								if ((v == '') || ( 0 != v && (v < 1280) || (v > 1500)))
								{
									alert("MTU非法，请输入值为1280~1500之间的整数！(或0默认)");
									return false;
								}
							}
						}
					}				
				}
			}

			if ( 'none' != getElement('PDEnableSec').style.display )
			{
				PDUsed.value = 'Yes';
				if (getCheckVal('cb_enabledpd') == 1)
					enablepd.value = 'Yes';
				else
					enablepd.value = 'No';		
			}
			else
				PDUsed.value = 'No';

			if ( 'none' != getElement('pdmode_1').style.display )
			{
				pdmodeUsed.value = 'Yes';
				if ( getRadioVal('pdmode') == 'No' )
				{
					var prefixObjs = pdprefix.value.split('/');
					if ( prefixObjs.length != 2 )
					{
						alert("前缀地址非法！格式为XXXX.XXXX.XXXX.XXXX::/XX");
						return false;	
					}

					if ( true != isGlobalIpv6Address(prefixObjs[0]) )
					{
						alert("前缀IP格式非法！格式为XXXX.XXXX.XXXX.XXXX::");
						return false;
					}

					var TemLen = parseInt(prefixObjs[1]);
					if ( true != isPlusInteger(prefixObjs[1]) || true == isNaN(TemLen) || TemLen > 64 || TemLen < 16)
					{
						alert("前缀长度非法！长度为16-64");
						return false;	
					}
					
					switch ( CheckPDTime(pdprefixptime.value, pdprefixvtime.value) )
					{
						case 1 :
							alert('前缀首选寿命 : "' + pdprefixptime.value + '" 不合法 !');
							return false;
						case 2 :
							alert('前缀有效寿命 : "' + pdprefixvtime.value + '" 不合法 !');
							return false;
						case 3 :
							alert('前缀有效寿命 : ' + pdprefixvtime.value + '必须大于前缀首选寿命 : ' + pdprefixptime.value);
							return false;
					}
				}
			}
			else
				pdmodeUsed.value = 'No';
				if ( 'none' != getElement('enabledhcpsec').style.display )
				{
					if (getCheckVal('cb_enabledhcp') == 1)
						enable_dhcp.value = '1';
					else
						enable_dhcp.value = '0';
				}
				else
					enable_dhcp.value = '0';

			if (getElement('secPppoeItems').style.display != "none")
			{
				if (getElement('secIdleTime').style.display != "none")
				{
					if (isPlusInteger(pppTimeOut.value) == false)
					{
						alert("空闲超时非法！");
						return false;
					}
					else
					{
						if ((getElement('pppTimeOut').value < 1) || (getElement('pppTimeOut').value > 4320)
						|| (getElement('pppTimeOut').value == ''))
						{
							alert("空闲超时非法！");
							return false;
						}
					}

				}		
				if (isValidNameEx(pppUserName.value) == false)
				{
					alert("用户名非法");
					return false;
				}
				if (isValidNameEx(pppPassword.value) == false)
				{
					alert("密码非法");
					return false;
				}
				if (isValidNameEx(pppServiceName.value) == false)
				{
					alert("服务名称非法");
					return false;
				}
				setTextContent('encodePppUserName', encode64(pppUserName.value));
				setTextContent('encodePppPassword', encode64(pppPassword.value));				
			}
			
			if ((getElement('secStaticItems').style.display != "none")
			&& ("IPv6" != getRadioVal("IpVersion")))
			{
				if (WanIP != null)
				{
					var iloop;
					for (iloop = 0; iloop< WanIP.length-1; iloop++)
					{
						if ( wanIpAddress.value == WanIP[iloop].wanIpAddress)
						{
							alert("IP地址和" + WanIP[iloop].conName + "冲突!") ;
							return false;
						}
					}
				}

				//if (!isAbcIpAddress(wanIpAddress.value))
				if (!sji_checkvip(wanIpAddress.value))
				{
					alert("IP地址非法！");
					wanIpAddress.focus();
					return false;
				}
				
				//if (!isValidSubnetMask(wanSubnetMask.value))
				if (!sji_checkmask(wanSubnetMask.value))
				{
					alert("子网掩码非法！");
					wanSubnetMask.focus();
					return false;
				}
/*				
				if (!isHostIpWithSubnetMask(wanIpAddress.value, wanSubnetMask.value))
				{
					alert("IP地址和子网掩码不匹配");
					wanIpAddress.focus();
					return false;
				}
	*/			
				//if (!isAbcIpAddress(defaultGateway.value))
				if (!sji_checkvip(defaultGateway.value))
				{
					alert("缺省网关非法！");
					defaultGateway.focus();
					return false;
				}
				
				//if (!isAbcIpAddress(dnsPrimary.value))
				if (!sji_checkvip(dnsPrimary.value))
				{
					alert("首选DNS服务器地址非法！");
					dnsPrimary.focus();
					return false;
				}
				
				if (!isUseableIpAddress(dnsPrimary.value))
				{
					alert("首选DNS服务器地址非法！");
					dnsPrimary.focus();
					return false;
				}
				
				//if (dnsSecondary.value != '' && !isAbcIpAddress(dnsSecondary.value))
				if (dnsSecondary.value != '' && !sji_checkvip(dnsSecondary.value))
				{
					alert("备用DNS服务器地址非法！");
					dnsSecondary.focus();
					return false;
				}
				
				if (dnsSecondary.value != '' && !isUseableIpAddress(dnsSecondary.value))
				{
					alert("备用DNS服务器地址非法！");
					dnsSecondary.focus();
					return false;
				}
			}
			
			if ((secIPv6Div.style.display != "none"))
			{
				if ('IPv4' != getRadioVal('IpVersion'))
				{
					if (TrIpv6Addr.style.display != "none")
					{
						if (!isGlobalIpv6Address(getValue('IdIpv6Addr')))
						{
							alert("IPv6地址不正确!");
							return false;
						}
						
						var v = getValue('IdIpv6PrefixLen');
						if(isPlusInteger(v) == false)
						{
							alert("IPv6前缀长度不正确!");
							return false;
						}
						else
						{
							if ((v == "") || (v <= 0) || (v > 128))
							{
								alert("IPv6前缀长度不正确!");
								return false;
							}
							
							if (v.length > 1 && v.charAt(0) == '0')
							{
								alert("IPv6前缀长度不正确!");
								return false;
							}
						}
						
						if (!isUnicastIpv6Address(getValue('IdIpv6Dns1')))
						{
							alert("IPv6首选DNS服务器地址不正确");
							return false;
						}
						
						var v1 = getValue('IdIpv6Dns2');
						if (v1 != '' && !isUnicastIpv6Address(v1))
						{
							alert("IPv6备用DNS服务器地址不正确");
							return false;
						}
					}
					
					var v2 = getValue('IdIpv6Gateway');
					if (v2 != '' && !isUnicastIpv6Address(v2))
					{
						alert("IPv6默认网关不正确");
						return false;
					}
				}
			}
				
			if ( 'none' != getElement('dslite_1').style.display )
			{
				if (getCheckVal('cb_enabledslite') == 1)
					enabledslite.value = 'Yes';
				else
					enabledslite.value = 'No';

				dsliteUsed.value = 'Yes';
			}
			else
				dsliteUsed.value = 'No';

			if ( 'none' != getElement('ppp_bi').style.display )
			{
				pppbiUsed.value = 'Yes';
				if ( getCheckVal('cb_enable_pppbi') == '1' )
				{
					if ( 1 == checkDupPPPBi() )
					{
							alert("仅支持1条WAN连接开启桥混合模式");
							return false;
					}
					enablepppbi.value = 'Yes';
				}
				else
					enablepppbi.value = 'No';
			}
			else
				pppbiUsed.value = 'No';
		}



		mode = getSelectVal('wanMode');
		ipMode = getRadioVal('IpMode');
		brMode = getSelectVal('bridgeMode');
		var type = getLinkType(mode,ipMode,brMode);
		var wanType = getWanType(mode,ipMode,brMode);
		var BindArray = new Array();
		var j = 0;
		
		for (var i = 1; i <= ssidShowNum; i++)
		{
			var len = 'InternetGatewayDevice.LANDevice.1.'.length;
			if (getCheckVal('cb_bindlan'+i) == 1)
				BindArray[j++] = getValue('cb_bindlan'+i).substr(len);
			if (getCheckVal('cb_bindwireless'+i) == 1)
				BindArray[j++] = getValue('cb_bindwireless'+i).substr(len);
		}
		if (BindArray.length > 0)
		{
			for (var j = 0; j < Wan.length; j++)
			{
				if ((j != SelWanIndex) && (Wan[j].bind != ""))
				{
					if (mode == "Bridge")
					{
						for (i = 0; i < BindArray.length; i++)
						{
							if (Wan[j].bind.indexOf(BindArray[i]) >= 0)
							{
								alert('绑定选项与其他WAN连接的绑定选项冲突，请重新选择绑定接口，如果所有绑定选项皆被其他WAN绑定，则不能进行任何绑定！');
								return false;
							}
						}
					}
					else
					{
						if (getRadioVal('IpVersion') == 'IPv4')
						{
							if ((Wan[j].ConnectionType.indexOf("Bridge") >= 0)
							|| (Wan[j].xIpv4Enable == 1))
							{
								for (i = 0; i < BindArray.length; i++)
								{
									if (Wan[j].bind.indexOf(BindArray[i]) >= 0)
									{
										alert('绑定选项与其他WAN连接的绑定选项冲突，请重新选择绑定接口，如果所有绑定选项皆被其他WAN绑定，则不能进行任何绑定！');
										return false;
									}
								}
							}
						}
						else if (getRadioVal('IpVersion') == 'IPv6')
						{
							if ((Wan[j].ConnectionType.indexOf("Bridge") >= 0)
							|| (Wan[j].xIpv6Enable == 1))
							{
								for (i = 0; i < BindArray.length; i++)
								{
									if (Wan[j].bind.indexOf(BindArray[i]) >= 0)
									{
										alert('绑定选项与其他WAN连接的绑定选项冲突，请重新选择绑定接口，如果所有绑定选项皆被其他WAN绑定，则不能进行任何绑定！');
										return false;
									}
								}
							}
						}
						else
						{
							for (i = 0; i < BindArray.length; i++)
							{
								if (Wan[j].bind.indexOf(BindArray[i]) >= 0)
								{
									alert('绑定选项与其他WAN连接的绑定选项冲突，请重新选择绑定接口，如果所有绑定选项皆被其他WAN绑定，则不能进行任何绑定！');
									return false;
								}
							}
						}
					}
				}
			}
		}

		return true;
	}

	function ManualConnectSubmit()
	{
		if (AddFlag == true)
		{
			return;
		}
		setDisable('btnRemoveCnt',1);
		setDisable('btnOK',1);
		setDisable('btnAddCnt',1);
		setDisable('pppDialButton',1);
		setDisable('pppLinkDownButton',1);
		document.ConfigForm.Wan_Flag.value = "3";
		document.ConfigForm.submit();
	}

	function ManualDisconnectSubmit()
	{
		if (AddFlag == true)
		{
			return;
		}
		setDisable('btnRemoveCnt',1);
		setDisable('btnOK',1);
		setDisable('btnAddCnt',1);
		setDisable('pppDialButton',1);
		setDisable('pppLinkDownButton',1);
		document.ConfigForm.Wan_Flag.value = "4";
		document.ConfigForm.submit();
	}
	
	function resetTextContent()
	{
		var Inputs = document.getElementsByTagName("input");
		for (var i = 0; i < Inputs.length; i++)
		{
			if (Inputs[i].type == "text" || Inputs[i].type == "password" )
			{
				Inputs[i].value = '';
			}
		}
	}
	
	function AddOption(selItem,value,text,ifSelected)
	{
		var option = document.createElement("option");
		option.innerHTML = text;
		option.value = value;
		option.selected = ifSelected;
		selItem.appendChild(option);
	}
	
	function RemoveOption(selItem,index)
	{
		selItem.removeChild(selItem.options[index]);
	}
	
	function CancelAddCnt()
	{
		with (getElById('ConfigForm'))
		{
			RemoveOption(getElement('wanId'),wanId.length - 1);
			AddFlag = false;
			btnAddCnt.disabled = false;
		}
	}
	
	function onCancel()
	{
		var wanIdItem = getElement('wanId');
		if (wanIdItem.value == -1)
		{
			CancelAddCnt();
			if (wanIdItem.length > 0)
			{
				WanIdChange();
			}
		}
		else 
			RefreshPage();
	}
	
	function getBind(bindstr,cb_str)
	{
		if (getCheckVal(cb_str) == 1)
		{
			if (bindstr == '')
			{
				return  getValue(cb_str);
			}
			else
			{
				return  ',' + getValue(cb_str);
			}
		}
		return '';
	}

	
	function getLinkType(mode,ipMode,brMode)
	{
		if (mode == "Route")
		{
			if (ipMode == 'PPPoA')
			{
				return 'PPPoA';
			}
			else if (ipMode == 'IPoA')
			{
				return 'IPoA';
			}
			else if (ipMode == 'CIP')
			{
				return 'CIP';
			}
			else
			{
				return 'EoA';
			}
		}
		else if (mode == "Bridge")
		{
			return 'EoA';
		}
	}
	
	function getWanType(mode,ipMode,brMode)
	{
		var LinkType = getLinkType(mode,ipMode,brMode);
		if (mode == 'Bridge' && LinkType == 'EoA')
		{
			if (brMode == 'IP_Bridged')
			{
				return 'WANIPConnection';
			}
			else
			{
				return 'WANPPPConnection';
			}
		}
		if ((LinkType == 'EoA' && ipMode == 'PPPoE') || (LinkType == 'PPPoA'))
		{
			return 'WANPPPConnection';
		}
		else if ((LinkType == 'EoA' && ipMode != 'PPPoE') || (LinkType == 'IPoA') || (LinkType == 'CIP'))
		{
			return 'WANIPConnection';
		}
	}
	
	function VLANModeChg()
	{
		with (getElById('ConfigForm'))
		{
			switch (VLANMode.value)
			{
				case 'TAG':
					setDisplay('vlansec', 1);
					setDisplay('priosec', 1);
					vlanId.value = "Yes";
					vlanPri.value = "Yes";
				if ( 0 == v8021P.value.length )
					v8021P.value = '0';
				break;

				case 'UNTAG':
				case 'TRANSPARENT':
					setDisplay('vlansec', 0);
					setDisplay('priosec', 0);
					vlanId.value = "No";
					vlanPri.value = "No";
				break;

				default:
				break;
			}
		}
	}

	var isNeedChange = 0;
	function MTUDispChange()
	{
		var mtudescrip = new Array('MTU[128-1492]：', 'MTU[576-1500]：', 'MTU[1280-1492]：', 'MTU[1280-1500]：','MTU[1320-1452]：','MTU[1320-1460]：');
		with (getElById('ConfigForm'))
		{
			if ( 'Route' == wanMode.value )
			{
				setDisplay('MTUsec', 1);
				if (AddFlag == true || isNeedChange)
				{
					isNeedChange = false;
					if (getSelectVal('linkMode') == 'linkPPP')
						MTU.value = 1492;
					else
						MTU.value = 1500;
				}

				if (getSelectVal('linkMode') == 'linkPPP')
				{
					if ('IPv4' == getRadioVal('IpVersion'))
						getElement("MIUDescrip").innerHTML = mtudescrip[0];
					else{

						if (getCheckVal('cb_enabledslite') == 1){
							getElement("MIUDescrip").innerHTML = mtudescrip[4];	
						}else
						{
							getElement("MIUDescrip").innerHTML = mtudescrip[2];
						}
					}
				}
				else
				{
					if ('IPv4' == getRadioVal('IpVersion'))			
						getElement("MIUDescrip").innerHTML = mtudescrip[1];
					else{

						if (getCheckVal('cb_enabledslite') == 1){
							getElement("MIUDescrip").innerHTML = mtudescrip[5];	
						}else{
							getElement("MIUDescrip").innerHTML = mtudescrip[3];		
						}

					}
				}
			}
			else
			{
				setDisplay('MTUsec', 0);
			}
		}
	}

	function MultiVIDDispChange()
	{
		var svrList;

		with (getElById('ConfigForm'))
		{
			svrList = serviceList.value;
			if ( svrList.indexOf('INTERNET') >= 0 || svrList.indexOf('OTHER') >= 0 || svrList.indexOf('IPTV') >= 0 )
				setDisplay('mulvidsec', 1);
			else
				setDisplay('mulvidsec', 0);
		}
	}

	function dsliteShow()
	{
		var ipVer;
		var svrList;
		var mode;
		var addrType;

		ipVer = getRadioVal('IpVersion');
		svrList = getSelectVal('serviceList');
		mode = getSelectVal('wanMode');

		if ( 'Route' == mode && 
			'IPv6' == ipVer && svrList.indexOf('INTERNET') >= 0)
		{
			setDisplay('dslite_1', 1);
			var modeObj = document.getElementsByName('dslitemode');
			if ( modeObj.length >= 2 )
			{
				modeObj[0].disabled = false;
				modeObj[1].disabled = false;
			}
			addrType = getSelectVal('IdIpv6AddrType');
			if ( 'Static' == addrType )
			{
				if ( modeObj.length >= 2 )
				{
					modeObj[0].disabled = true;
					modeObj[1].checked = true;
				}
			}
			cb_enabledsliteChange();
		}
		else
		{
			setDisplay('dslite_1', 0);
			setDisplay('dslite_2', 0);
			setDisplay('dslite_3', 0);
		}

	}

	function cb_enabledsliteChange()
	{
		with (getElById('ConfigForm'))
		{
			if ( 1 == getCheckVal('cb_enabledslite') )
			{
				setDisplay('dslite_2', 1);
				dslitemodeChange();
			}
			else
			{
				setDisplay('dslite_2', 0);
				setDisplay('dslite_3', 0);
			}
		}
		MTUDispChange();
	}

	function dslitemodeChange()
	{

		var mode;

		with (getElById('ConfigForm'))
		{
			mode = getRadioVal("dslitemode");
			switch (mode)
			{
				case '1':
					setDisplay('dslite_3', 1);
					break;
				default:
					setDisplay('dslite_3', 0);
					break;	
			}
		}
	 
	}

	var pdDefaultSel = 0;
	function pdEnableShow()
	{
		var ipVer;
		var mode;
		var svrList;

		ipVer = getRadioVal('IpVersion');
		mode = getSelectVal('wanMode');
		svrList = getSelectVal('serviceList');
		addrType = getSelectVal('IdIpv6AddrType');

		if ( 'Route' == mode && 'IPv4' != ipVer
			&& (svrList.indexOf('INTERNET') >= 0 || svrList.indexOf('OTHER') >= 0) )
		{
			setDisplay('PDEnableSec', 1);
			if ( svrList.indexOf('INTERNET') >= 0 && 1 == pdDefaultSel )
				setCheckContent('cb_enabledpd', 1);
			pdDefaultSel = 0;
			pdModeShow( getCheckVal('cb_enabledpd') );	
		}
		else
		{
			setDisplay('PDEnableSec', 0);
			pdModeShow(0);
		}
	}

	function cb_pdEnableChange()
	{
			var pdEnable = getCheckVal('cb_enabledpd');
			pdModeShow(pdEnable);

	}

	function pdModeShow( show )
	{
		addrType = getSelectVal('IdIpv6AddrType');
/*		//disable auto/manual mode for PD
		if ( 1 == show )
		{
			setDisplay('pdmode_1', 1);
			var modeObj = document.getElementsByName('pdmode');
			if ( modeObj.length >= 2 )
			{
				modeObj[0].disabled = false;
				modeObj[1].disabled = false;
			}

			if ( 'Static' == addrType )
			{
				if ( modeObj.length >= 2 )
				{
					modeObj[0].disabled = true;
					modeObj[1].checked = true;
				}
			}

			pdmodeChange();
		}
		else */
		{
			setDisplay('pdmode_1', 0);
			pdStaticCfgShow(0);
		}
	}

	function pdmodeChange()
	{
		var pdmode_sel;

		pdmode_sel = getRadioVal('pdmode');
		if ( 'No' == pdmode_sel )
			pdStaticCfgShow(1);
		else
			pdStaticCfgShow(0);
	}

	function pdStaticCfgShow( show )
	{
		setDisplay('pdmode_2', show);
		setDisplay('pdmode_3', show);
		setDisplay('pdmode_4', show);
	}

	function CheckPDTime(Time1,Time2)
	{
		var TemTime1 = Time1;
		var TemTime2 = Time2;

		if ( TemTime1.length > 10 || '' == TemTime1 )
			return 1;
		if ( TemTime2.length > 10 || '' == TemTime2 )
			return 2;
		if ( true != isPlusInteger(TemTime1))
			return 1;
		if ( true != isPlusInteger(TemTime2))
			return 2;

		TemTime1 = parseInt(Time1);
		TemTime2 = parseInt(Time2);
		if ( TemTime1 > 4294967295 || TemTime1 < 600 )
			return 1;
		if ( TemTime2 > 4294967295 || TemTime2 < 600 )
			return 2;
		if ( TemTime2 <= TemTime1 )
				return 3;

		return true;
	}

	var enabledhcpSel = 0;
	function dhcpEnableShow()
	{

		var svrList;

		svrList = getSelectVal('serviceList');

		if ( 'TR069' == svrList
			|| 'VOIP' == svrList
			|| 'TR069_VOIP' == svrList )
		{
			setDisplay('enabledhcpsec', 0);
			setCheckContent('cb_enabledhcp', 0);
		}
		else
		{
			setDisplay('enabledhcpsec', 1);
			if ( 1 == enabledhcpSel )
			{
				enabledhcpSel = 0;
				if ( svrList.indexOf('OTHER') >= 0 )
					setCheckContent('cb_enabledhcp', 0);
				else
					setCheckContent('cb_enabledhcp', 1);
			}
		}

	}

	function pppoeProxyShow()
	{
		pppbiShow();
	}

	function pppbiShow()
	{
		var mode;
		var linkMode;
		var svrList;

		mode = getSelectVal('wanMode');
		linkMode = getSelectVal('linkMode');
		svrList = getSelectVal('serviceList');

		if ( 'Route' == mode && 'linkPPP' == linkMode
		   && (svrList.indexOf('INTERNET') >= 0 || svrList.indexOf('OTHER') >= 0) )
			setDisplay('ppp_bi', 1);
		else
			setDisplay('ppp_bi', 0);
	}

	function ppp_dialMethodChg()
	{

	}
	
	var pvChanged = 0;//flag of ip version whether changed

	function CheckIpVersionState()
	{
		var vForm = document.ConfigForm;
		ipvChanged = 0;
		vForm.IPVersionValue.value = "IPv4";
		var vValue = getRadioVal("IpVersion");
		if(vForm.IPVersionValue.value != vValue){
			if(vForm.IPVersionValue.value == "IPv4")
				ipvChanged = 1;
			else if(vForm.IPVersionValue.value == "IPv6")
				ipvChanged = 2;
			else ipvChanged = 3;
		}
		vForm.IPVersionValue.value = vValue;
		
		with (getElById('ConfigForm'))
		{
			if(IdIpv6AddrType.value == "SLAAC")
				pppv6Mode.value = "No";
			else if(IdIpv6AddrType.value == "DHCP")
				pppv6Mode.value = "Yes";
			else
				pppv6Mode.value = "N/A";	
		}
		
	}
		
	function WanIndexConstruction(domain,WanName)
	{
		this.domain = domain;
		this.WanName = WanName;
	}
	
	function CheckWansActives()
	{

		var	nCurTemp = 0;
		var	vcurLinks = new Array(nEntryNum);
		for(var i=0; i<=nEntryNum; i++)
		{	
			vcurLinks[nCurTemp++] = new WanIndexConstruction(vEntryIndex[i], vEntryName[i]);
		}
		
		var	vObjRet = new Array(nCurTemp+1);
		for(var m=0; m<nCurTemp; m++)
		{
			vObjRet[m] = vcurLinks[m];
		}
		vObjRet[nCurTemp] = null;
		return vObjRet;
	}
	var	CurWan = CheckWansActives();
	var WanNameObjs;

	function WriteWanNameSelected()
	{
		var WanIDNums = CurWan;
		var nlength = WanIDNums.length-1;
		var i = 0;
		var isSel = 0;
		var gotopts = 0;
		if(nlength == 1) 
			document.ConfigForm.curSetIndex.value = WanIDNums[0].domain;
		
		WanNameObjs = new Array(nlength)
		for( i=0; i< nlength; i++)
		{
			WanNameObjs[i] = new WanNameObject(WanIDNums[i].domain, WanIDNums[i].WanName, IFIdxArray[i]);
		}

		with (getElById('wanId'))
		{
			for( i=0; i< WanNameObjs.length; i++)
			{
				var opt = new Option(WanNameObjs[i].IfaceName, WanNameObjs[i].IfaceDomain);
				if ( document.ConfigForm.curSetIndex.value == WanNameObjs[i].IfaceDomain )
				{
					opt.selected = true
					isSel = i;			
				}
				options.add ( opt );				
				gotopts = 1;
			}
			if ( gotopts )
			{
				options[isSel].setAttribute('selected', 'true');
			}
		}
	}

	function getIFIdxvidDomain(domain)
	{
		var i = 0;

		for( i=0; i< WanNameObjs.length; i++)

		{
			if ( domain == WanNameObjs[i].IfaceDomain )
				return WanNameObjs[i].IfaceIndex;
		}

		return 1;
	}

	function WanNameObject(IFDomain, IFName, IFIdx)
	{
		this.IfaceDomain = IFDomain;
		this.IfaceName = IFName;
		this.IfaceIndex = IFIdx;
	}

	function v4v6BindCheck(curindex, v4BindIdx, v6BindIdx)
	{

		if ( ( curindex == v4BindIdx && (-1 == v6BindIdx ) )
			|| ( curindex == v4BindIdx && curindex == v6BindIdx )
			|| ( curindex == v6BindIdx && (-1 == v4BindIdx ) )
			|| ( curindex == v6BindIdx && curindex == v4BindIdx ) )
			return 1;

		return 0;

	}

	//type: 
	//0: Add action
	//1: Modify action
	function checkBandBoxStatus(type)
	{
	//lan
		var strCurBind = "";

		var aCurBindFlag = new Array(12);

		aCurBindFlag[0] = "No";
		if(aCurBindFlag[0] != "N/A")
		{
			aCurBindFlag[1] = "No";
			aCurBindFlag[2] = "No";
			aCurBindFlag[3] = "No";
			aCurBindFlag[4] = "No";
			aCurBindFlag[5] = "No";
			
			aCurBindFlag[8] = "N/A";
			for(k=0; k<12; k++)
			{
				strCurBind = strCurBind + aCurBindFlag[k] + ",";
			}
		}
		
		var strBindFlag = "";
		var nInterfaces = CurWan.length-1;
		var vForm = document.ConfigForm;
		if(vForm.cb_bindlan1.checked)
			vForm.bindlan1.value = "Yes";
		else vForm.bindlan1.value = "No";
		strBindFlag = strBindFlag + vForm.bindlan1.value + ",";
		if(vForm.cb_bindlan2.checked)
			vForm.bindlan2.value = "Yes";
		else vForm.bindlan2.value = "No";
		strBindFlag = strBindFlag + vForm.bindlan2.value + ",";
		if(vForm.cb_bindlan3.checked)
			vForm.bindlan3.value = "Yes";
		else vForm.bindlan3.value = "No";
		strBindFlag = strBindFlag + vForm.bindlan3.value + ",";
		if(vForm.cb_bindlan4.checked)
			vForm.bindlan4.value = "Yes";
		else vForm.bindlan4.value = "No";
		strBindFlag = strBindFlag + vForm.bindlan4.value + ",";
	//wireless
		if(vForm.cb_bindwireless1.checked)
			vForm.bindwireless1.value = "Yes";
		else vForm.bindwireless1.value = "No";
		strBindFlag = strBindFlag + vForm.bindwireless1.value + ",";

		if(vForm.cb_bindwireless2.checked)
			vForm.bindwireless2.value = "Yes";
		else vForm.bindwireless2.value = "No";	
		strBindFlag = strBindFlag + vForm.bindwireless2.value + ",";

		strBindFlag = strBindFlag + ",No,No,";
	//wireless 5g
		if(vForm.cb_bindwirelessac1.checked)
			vForm.bindwirelessac1.value = "Yes";
		else vForm.bindwirelessac1.value = "No";
		strBindFlag = strBindFlag + vForm.bindwirelessac1.value + ",";
		
		var aTemp1 = new Array();
		var aTemp2 = new Array();
		var aTemp3 = new Array();
		

		
		if(vBindStatus != "N/A")
		{
			aTemp1 = vBindStatus.split(',');
			aTemp2 = strBindFlag.split(',');
			aTemp3 = strCurBind.split(',');
			//check ip version;
			var strIpversion = vForm.IPVersionValue.value;//current ip version;

			if ( 'none' != getElement('dslite_1').style.display )
			{
				if (getCheckVal('cb_enabledslite') == 1)
						strIpversion = "IPv4/IPv6";
			}	

			
			
			for(var i=0; i<14; i++)

			{
				
				if((aTemp1[i] == "Yes") && (aTemp2[i] == "Yes"))
				{

					if (1 == type) // modify action
					{
		
						if ( ("IPv4" == strIpversion && vForm.curSetIndex.value == parseInt(aTemp1[42+2*i]))
							 || ("IPv6" == strIpversion && vForm.curSetIndex.value == parseInt(aTemp1[42+2*i+1]))
							 || ("IPv4/IPv6" == strIpversion && v4v6BindCheck(vForm.curSetIndex.value, parseInt(aTemp1[42+2*i]), parseInt(aTemp1[42+2*i+1]))) )
							continue;
					}					
					if((("IPv4" == strIpversion) && (0 == aTemp1[14+2*i])) || (("IPv6" == strIpversion) && (0 == aTemp1[14+2*i+1]))){				
						continue;
					}
						
					var strindex;
					if(i < 4)
					{
						strindex = i+1;
						alert("Lan" + strindex.toString() + "已被其它Interface绑定，不能重复绑定！");
					}
						
					else if(i >=4 && i < 8)
					{
						strindex = i - 3;
						alert("SSID" + strindex.toString() + "已被其它Interface绑定，不能重复绑定！");
					}
					else
					{
						strindex = i - 9;
						alert("SSIDAC" + strindex.toString() + "已被其它Interface绑定，不能重复绑定！");
					}

					return false;
				}
			}	
		}
		return true;
	}

	function btnSave()
	{
		if(CheckForm(1) == false)
			return false;			
		CheckIpVersionState();
		cb_enblServiceChange();
		EnableDHCPRealy();		
		
		var	vForm = document.ConfigForm;

		if(vForm.linkMode.value == "linkPPP")
		{
			DialMethodChange();
			setTextContent('pppManualStatus_Flag', 'disconnect');
		}
		vForm.Wan_Flag.value = "1";
		if(AddFlag == true){	
			vForm.OperatorStyle.value = "Add";//add new
			if(checkBandBoxStatus(0) == false)
				return false;
			vForm.WanCurrIFIdx.value = getMaxIFIdx();
		}
		else{
			vForm.OperatorStyle.value = "Modify";//modify
			if(checkBandBoxStatus(1) == false)
				return false;
		}
		setDisable('btnRemoveCnt',1);
		setDisable('btnOK',1);
		setDisable('btnAddCnt',1);
		vForm.submit();
	}

	function btnAddWanCnt()
	{
		if ((CurWan.length-1) >= 8)
		{
			alert("您最多只能建立8条WAN连接！");
			return;
		}
		if (AddFlag == true)
		{
			alert("请您保存新建连接后再进行新的添加！");
			return;
		}
	
		AddFlag = true;
		$("#enableDisplay *").prop("disabled", false);
		resetTextContent();
		with (getElById('ConfigForm'))
		{
			AddOption(getElementByName('wanId'),-1,'新建WAN连接',true);
			btnAddCnt.disabled = true;
			setSelectContent('linkMode', 'linkPPP');	

			setSelectContent('serviceList','INTERNET');
			setTextContent('ConnectionFlag', "Connect_Keep_Alive");
			setCheckContent('cb_enblService',1);
			setSelectContent('wanMode',"Route");
			setSelectContent('bridgeMode', "PPPoE_Bridged");

			lockObj('pppUserName',false);
			lockObj('pppPassword',false);
			lockObj('DialMethod',false);
			lockObj('pppTimeOut',false);
			lockObj('vlan',false);
			SelWanIndex = -1;
			enabledhcpSel = 1;
			WanModeChange();
			onChangeSvrList();
			IpMode[2].checked = true;
			IpModeChange();
			VLANModeChg();
			for (var i = 0; i < ssidShowNum; i++)
			{
				var checkString = 'cb_bindlan' + (i+1);
				setCheckContent(checkString,0);
				checkString = 'cb_bindwireless' + (i+1);
				setCheckContent(checkString,0);
			}
			checkString = 'cb_bindwirelessac' + (1);
			setCheckContent(checkString,0);			
			setRadioContent('pdmode', 'Yes');
			document.getElementById("table8").focus();
		}
	}

	function btnRemoveWanCnt()
	{
		if ((CurWan.length - 1) == 0)
		{
			alert("无法删除，您未添加任何WAN连接！");
			return;
		}
		if (AddFlag == true)
		{
			alert("新建WAN连接并未保存，不能进行删除操作！");
			return;
		}
		if (confirm("您是否确认要删除此条WAN连接？") == false)
			return;

		var	vForm = document.ConfigForm;
		vForm.Wan_Flag.value = "3";
		for(var i=0; i<(CurWan.length-1); i++)
		{
			if(CurWan[i].domain != vForm.curSetIndex.value)
			{
				vForm.afterdeleteFlag.value = CurWan[i].domain;
				break;
			}
		}
		setDisable('btnRemoveCnt',1);
		setDisable('btnOK',1);
		setDisable('btnAddCnt',1);
		vForm.OperatorStyle.value = "Del";
		vForm.submit();
	}

	function OnIPv6Changed()
	{
		with (getElById('ConfigForm'))
		{
			var linkstr = getSelectVal('linkMode');
			var AddrType = getSelectVal('IdIpv6AddrType');
			if (AddrType == 'SLAAC')
			{
				setDisplay('TrIpv6Addr', 0);
				setDisplay('TrIpv6Dns1', 0);
				setDisplay('TrIpv6Dns2', 0);
				setDisplay('TrIpv6GatewayInfo', 0);
				setDisplay('TrIpv6Gateway', 0);
				ISPTypeValue.value = "0";
			}
			else if (AddrType == 'DHCP')
			{
				setDisplay('TrIpv6Addr', 0);
				setDisplay('TrIpv6Dns1', 0);
				setDisplay('TrIpv6Dns2', 0);
				setDisplay('TrIpv6Gateway', 0); //iulian marked, not support yet
				setDisplay('TrIpv6GatewayInfo', 0); //iulian marked, not support yet
				ISPTypeValue.value = "0";
			}
			else if (AddrType == 'Static')
			{
				setDisplay('TrIpv6Addr', 1);
				setDisplay('TrIpv6Dns1', 1);
				setDisplay('TrIpv6Dns2', 1);
				setDisplay('TrIpv6Gateway', 1);
				setDisplay('TrIpv6GatewayInfo', 0);
				ISPTypeValue.value = "1";
			}
			dsliteShow();
			pdEnableShow();
		}
	}
	function WriteIPv6List(index)
	{
		var vmode = new Array("No", "Yes", "N/A");
		var ctrl = getElById('IdIpv6AddrType');
		for(var i=0; i<ctrl.options.length;)
		{
			ctrl.removeChild(ctrl.options[i]);
		}
		if(index == 0)
		{
			var aMenu = new Array("SLAAC","DHCP");
			for(i=0; i<aMenu.length; i++)
			{
				ctrl.options.add(new Option(aMenu[i],aMenu[i]));
				if(vCurrentDHCPv6 == vmode[i])
				{
					document.ConfigForm.IdIpv6AddrType.selectedIndex = i;
				}
			}
		}
		else if(index == 1)
		{
			var aMenu = new Array("SLAAC","DHCP","Static");
			for(i=0; i<aMenu.length; i++)
			{
				ctrl.options.add(new Option(aMenu[i],aMenu[i]));
				if(vCurrentDHCPv6 == vmode[i])
				{
					document.ConfigForm.IdIpv6AddrType.selectedIndex = i;
				}
			}
		}
		else if(index == 2)
		{
			var aMenu = "Static";
			ctrl.options.add(new Option(aMenu,aMenu));
		}
		OnIPv6Changed();
	}
	
	function isTr069Configurable()
	{
		with (getElById('ConfigForm'))
		{
			var wanIdItem = getElement('wanId');

			if (serviceList.value == "TR069" || serviceList.value == "TR069_VOIP" ||
					serviceList.value == "TR069_INTERNET" || serviceList.value == "TR069_VOIP_INTERNET")
			{
				if(tr069Configurable==0 && wanIdItem.value != -1){
					$("#enableDisplay *").prop("disabled", true);
					setDisplay('btnRemoveCnt', 0);
					setDisplay('btnOK', 0);
					setDisplay('btnCancel', 0);
				}
				else{
					$("#enableDisplay *").prop("disabled", false);
					setDisplay('btnRemoveCnt', 1);
					setDisplay('btnOK', 1);
					setDisplay('btnCancel', 1);		
				}
			}
			else{
				$("#enableDisplay *").prop("disabled", false);
					setDisplay('btnRemoveCnt', 1);
					setDisplay('btnOK', 1);
					setDisplay('btnCancel', 1);			
			}
		}
	}

	function WanIdChange()
	{

		document.ConfigForm.Wan_Flag.value  = "2";
		//document.ConfigForm.curSetIndex.value = getSelectVal('wanId');	
		document.ConfigForm.curSetIndex.value = document.getElementById('wanId').selectedIndex;	//for IE.8
		//SelWanIndex = getSelectVal('wanId');
		SelWanIndex= document.getElementById('wanId').selectedIndex; //for IE.8
		LoadFrame();
	}

	function lockObj(objName, readST)
	{
		if ( null != getElById(objName) )
		{
			getElById(objName).readOnly = readST;
			getElById(objName).style.color = readST ? 'gray' : '';
		}
	}
</SCRIPT>
      <TABLE height="100%" cellSpacing=0 cellPadding=0 border=0 class="tblMain">
          <TBODY>
        <TR>
          <TD width="828px"><TABLE height="100%" cellSpacing=0 cellPadding=0 border=0>
              <TBODY>
                <TR>
					<TD vAlign=top><FORM name=ConfigForm action="/boaform/admin/formEthernet_cmcc" method="post">
                      <TABLE cellSpacing=0 cellPadding=0 width="800" border=0>
                        <TBODY>
                          <TR>
                            <TD width=20>&nbsp;</TD>
                            <TD><TABLE cellSpacing=0 cellPadding=0 border=0>
                                <TBODY>
                                  <TR>
                                    <TD width=150>连接名称：
                                      <input type="hidden" name="curSetIndex" value="1">
                                      <input type="hidden" name="WanActive" value="Yes">
                                      <input type="hidden" name="WanCurrIFIdx" value='1'>
									  <input type="hidden" name="wanName">
									  </TD>
                                    <TD><select onChange=WanIdChange()  name=wanId id='wanId' >
                                      </select>
                                      <script language="JavaScript" type="text/javascript">
										WriteWanNameSelected();
									</script></TD>
                                    <TD class="addwan"><INPUT id=btnAddCnt onclick="btnAddWanCnt()" type=button value="新建"></TD>
                                  </TR>
                                </TBODY>
                              </TABLE>
                              <input type="hidden" name="Wan_Flag" value="0">
                              <input type="hidden" name="ConnectionFlag" value="N/A">
                              <input type="hidden" name="afterdeleteFlag" value="0">
                              <input type="hidden" name="OperatorStyle" value="Add">
                              <input type="hidden" name="dhcpv6pdflag" value="Yes">
                              <input type="hidden" name="pppManualStatus_Flag" value="N/A">
							  <DIV id=enableDisplay>
                              <TABLE cellSpacing=0 cellPadding=0 width="100%" border=0>
                                <TBODY>
                                  <TR>
                                    <TD width=150>模式：</TD>
                                    <TD width=200><LABEL>
                                        
                                        <select id=select2 onChange=WanModeSelect() name="wanMode">
                                          <option value="Route" selected>Route
                                          <option value="Bridge" >Bridge
                                        </select>
                                        
                                      </LABEL></TD>
                                    <TD>启用：
                                      <LABEL>
                                        <INPUT id=cb_enblService onclick=cb_enblServiceChange() type=checkbox name=cb_enblService checked>
                                        <input id=enblService type=hidden name="enblService">
                                      </LABEL></TD>
                                  </TR>
                                </TBODY>
                              </TABLE>
                              <TABLE cellSpacing=0 cellPadding=0 width="100%" border=0>
                                <TBODY>
                                  <TR>
                                    <TD width=150>承载业务：</TD>
                                    <TD><LABEL>
                                        <SELECT id=serviceList onchange=onSelectSvrList() name='serviceList'>
                                        </SELECT>
                                      </LABEL></TD>
                                    <TD>&nbsp;</TD>
                                  </TR>
                                </TBODY>
                              </TABLE>
                              <TABLE style="DISPLAY: none" height=32 cellSpacing=0 cellPadding=0 width="100%" border=0>
                                <TBODY>
                                  <TR>
                                    <TD width=150 height="32">启用绑定：</TD>
                                    <TD width=306><LABEL>
                                        <INPUT id=cb_bindflag onclick=cb_bindflagChange() type=checkbox name="cb_bindflag" >
                                        <INPUT id=bindflag type=hidden value="N/A" name="bindflag">
                                      </LABEL></TD>
                                  </TR>
                                </TBODY>
                              </TABLE>
                              <DIV id=secBind>
                                <TABLE cellSpacing=0 cellPadding=0 border=0>
                                  <TBODY>
                                    <TR>
                                      <TD width=150>绑定选项：</TD>
                                      <TD colspan="4"><SPAN id=secLan1>
                                        <INPUT id=cb_bindlan1 type=checkbox name=cb_bindlan1 >
                                        LAN1
                                        <INPUT id=bindlan1 type=hidden value=0 name=bindlan1>
                                        </SPAN> &nbsp; <SPAN id=secLan2>
                                        <INPUT id=cb_bindlan2 type=checkbox  name=cb_bindlan2 >
                                        LAN2
                                        <INPUT id=bindlan2 type=hidden value=0 name=bindlan2>
                                        </SPAN> &nbsp; <SPAN id=secLan3>
                                        <INPUT id=cb_bindlan3 type=checkbox name=cb_bindlan3 >
                                        LAN3
                                        <INPUT id=bindlan3 type=hidden value=0 name=bindlan3>
                                        </SPAN> &nbsp; <SPAN id=secLan4>
                                        <INPUT id=cb_bindlan4 type=checkbox name=cb_bindlan4 >
                                        LAN4
                                        <INPUT id=bindlan4 type=hidden value=0 name=bindlan4>
                                        </SPAN></TD>
                                    </TR>
                                  </TBODY>
                                </TABLE>
                                <TABLE cellSpacing=0 cellPadding=0 border=0 id="wlanBindTab">
                                  <TBODY>
                                    <TR id = 'wlan_table_1'>
                                      <TD width=150>&nbsp;</TD>
                                      <TD colspan="4"><SPAN id=secWireless1>
                                        <INPUT id=cb_bindwireless1  type=checkbox name=cb_bindwireless1 >
                                        SSID1
                                        <INPUT id=bindwireless1 type=hidden value=0 name=bindwireless1>
                                        </SPAN> &nbsp;
										
                                        <DIV id=enableDisplay2> 
                                        <SPAN id=secWireless2>
                                        <INPUT id=cb_bindwireless2 type=checkbox name=cb_bindwireless2 >
                                        SSID2
                                        <INPUT id=bindwireless2 type=hidden value=0 name=bindwireless2>
                                        </SPAN> &nbsp;                                      
                                        </DIV>
                                        </TD>
                                    </TR>
                                  </TBODY>
                                </TABLE>
                                
                                <TABLE cellSpacing=0 cellPadding=0 border=0 id="wlanacBindTab">
                                  <TBODY>
                                    <TR id = 'wlan_table_2'>
                                      <TD width=150>&nbsp;</TD>
                                      <TD colspan="4"><SPAN id=secWirelessac1>
                                        <INPUT id=cb_bindwirelessac1 type=checkbox name=cb_bindwirelessac1 >
                                        SSID5
                                        <INPUT id=bindwirelessac1 type=hidden value=0 name=bindwirelessac1>
                                        </SPAN> &nbsp; </TD>
                                    </TR>
                                  </TBODY>
                                </TABLE>
                                
                              </DIV>
                              <TABLE height=30 cellSpacing=0 cellPadding=0 width="100%" 
                  border=0>
                                <TBODY>
                                  <TR id='enabledhcpsec'>
                                    <TD width=150 >DHCP Server启用： </TD>
                                    <TD><INPUT id='cb_enabledhcp' type=checkbox name='cb_enabledhcp' checked>
                                      <INPUT id='enable_dhcp' type=hidden name='enable_dhcp'>
									</TD>
                                  </TR>
                                </TBODY>
                              </TABLE>
                              <DIV id=divLink>
                                <TABLE height=30 cellSpacing=0 cellPadding=0 width="100%" 
                  border=0>
                                  <TBODY>
                                    <TR>
                                      <TD width=150>链接方式：</TD>
                                      <TD><LABEL>
                                          <SELECT id=linkMode onchange=linkModeSelect() name="linkMode">
                                            <OPTION value="linkIP" >通过IP方式建立链接
                                            <OPTION value="linkPPP" >通过PPP方式建立链接
                                          </SELECT>
                                        </LABEL></TD>
                                    </TR>
                                  </TBODY>
                                </TABLE>
                              </DIV>
                              <DIV id=divIpVersion>
                                <TABLE height=30 cellSpacing=0 cellPadding=0 width="100%" 
                  border=0>
                                  <TBODY>
                                    <TR>
                                      <TD width=150>IP协议版本：</TD>
                                      <TD><INPUT id=IpVersion onclick="pdDefaultSel=1;IpVersionChange();MTUDispChange();" type=radio value="IPv4" name="IpVersion" >
                                        IPv4&nbsp;&nbsp;
                                        
                                          <INPUT id=IpVersion onclick="pdDefaultSel=1;IpVersionChange();MTUDispChange();" type=radio value="IPv6" name="IpVersion" >
                                          IPv6&nbsp;&nbsp;
                                          <INPUT id=IpVersion onclick="pdDefaultSel=1;IpVersionChange();MTUDispChange();" type=radio value="IPv4/IPv6" name="IpVersion" >
                                          IPv4/IPv6&nbsp;&nbsp;
                                          </TD>
                                    </TR>
                                  </TBODY>
                                </TABLE>
                                <input type="hidden" name="IPVersionValue" value="IPv4/IPv6">
                                <input type="hidden" name="ISPTypeValue" value="0">
                              </DIV>
                              <DIV id=secIpMode>
                                <DIV id=secDhcp>
                                  <TABLE cellSpacing=0 cellPadding=0 width="100%" border=0>
                                    <TBODY>
                                      <TR>
                                        <TD width=150><INPUT onclick="IpModeChange()" type=radio value="DHCP" id="IpMode" name="IpMode" checked>
                                          DHCP</TD>
                                        <TD>从ISP处自动得到一个IP地址.</TD>
                                      </TR>
                                    </TBODY>
                                  </TABLE>
                                </DIV>
                                <DIV id=secStatic>
                                  <TABLE cellSpacing=0 cellPadding=0 width="100%" border=0>
                                    <TBODY>
                                      <TR>
                                        <TD width=150><INPUT onclick="IpModeChange()" type=radio value="Static" id="IpMode" name="IpMode" >
                                          Static</TD>
                                        <TD>经ISP配置一个静态的IP给你.</TD>
                                      </TR>
                                    </TBODY>
                                  </TABLE>
                                </DIV>
                                <DIV id=secPppoe>
                                  <TABLE cellSpacing=0 cellPadding=0 width="100%" border=0>
                                    <TBODY>
                                      <TR>
                                        <TD width=150><INPUT onclick="IpModeChange()" type=radio value="PPPoE" id="IpMode" name="IpMode" >
                                          PPPoE</TD>
                                        <TD>若ISP使用PPPoE请选择该项.</TD>
                                      </TR>
                                    </TBODY>
                                  </TABLE>
                                </DIV>
                                <DIV id=secPppoa>
                                  <TABLE style="DISPLAY: none" cellSpacing=0 cellPadding=0 
                  width="100%" border=0>
                                    <TBODY>
                                      <TR>
                                        <TD width=150><INPUT onclick="IpModeChange()" type=radio value="PPPoA" name="IpMode" >
                                          PPPoA</TD>
                                        <TD>若ISP使用PPPoA请选择该项.</TD>
                                      </TR>
                                    </TBODY>
                                  </TABLE>
                                </DIV>
                                <DIV id=secIpoa>
                                  <TABLE style="DISPLAY: none" cellSpacing=0 cellPadding=0 
                  width="100%" border=0>
                                    <TBODY>
                                      <TR>
                                        <TD width=150><INPUT onclick="IpModeChange()" type=radio  value="IPoA" name="IpMode" >
                                          IPoA</TD>
                                        <TD>若ISP使用IPoA请选择该项. </TD>
                                      </TR>
                                    </TBODY>
                                  </TABLE>
                                </DIV>
                                <BR>
                              </DIV>
                              <DIV id=secBridgeType style="DISPLAY: none">
                                <TABLE cellSpacing=0 cellPadding=0 width="100%" border=0>
                                  <TBODY>
                                    <TR>
                                      <TD width=150>桥类型：</TD>
                                      <TD><LABEL>
                                          <SELECT id=bridgeMode name="bridgeMode">
                                            <OPTION value="PPPoE_Bridged" >PPPoE_Bridged</OPTION>
                                            <OPTION value="IP_Bridged" >IP_Bridged</OPTION>
                                          </SELECT>
                                        </LABEL></TD>
                                    </TR>
                                  </TBODY>
                                </TABLE>
                              </DIV>
                              <DIV id=secbridgeDhcprelay style="DISPLAY: none">
                                <TABLE cellSpacing=0 cellPadding=0 width="100%" border=0>
                                  <TBODY>
                                    <TR>
                                      <TD width=150>使能DHCP透传：</TD>
                                      <TD><LABEL>
                                          <INPUT id=cb_dhcprelay type=checkbox name=cb_dhcprelay onClick="EnableDHCPRealy()" >
                                          <input type="hidden" name="dhcprelay" value="No">
                                        </LABEL></TD>
                                    </TR>
                                  </TBODY>
                                </TABLE>
                              </DIV>
                              <INPUT id=multMode type=hidden value=0 name=multMode>
                              <TABLE cellSpacing=0 cellPadding=0 width="100%" border=0>
                                <TBODY>
                                  <TR>
                                    <TD width=150>VLAN模式：</TD>
                                    <TD colspan='2'><select id='VLANMode' onChange="VLANModeChg()" size=1 name='VLANMode'>
                                        <option value="TAG" selected>TAG
                                        <option value="UNTAG"  >UNTAG
                                        <!-- <option value="TRANSPARENT" >TRANSPARENT () //iulian marked, not support yet)-->
                                      </select></TD>
                                  </TR>
                                  <TR id='vlansec'>
                                    <TD>VLAN ID[1-4094]：</TD>
                                    <TD colspan='2'><INPUT id=vlan maxLength=4 size=5 name=vlan>
                                      <INPUT id=vlanId type=hidden name=vlanId value="No">
                                      <INPUT id=vlanUNTAG type=hidden name=vlanUNTAG value="4096">
                                      <INPUT id=vlanTRANSPARENT type=hidden name=vlanTRANSPARENT value="4097"></TD>
                                  </TR>
                                  <TR id='priosec'>
                                    <TD>802.1p[0-7]：</TD>
                                    <TD colspan='2'><INPUT id=cb_8021P type=checkbox name=cb_8021P onClick="Enable8021PClick()" checked >
                                      使能
                                      &nbsp;
                                      <INPUT id=v8021PClick type=hidden name=v8021PClick value='Yes'>
                                      <INPUT id=v8021P maxLength=1 size=5 name=v8021P value="0">
                                      <INPUT id=vlanPri type=hidden name=vlanPri value="No">
                                      <INPUT id=vlanPriNone type=hidden name=vlanPriNone value="0"></TD>
                                  </TR>
                                  <TR id='mulvidsec'>
                                    <TD>组播VLAN ID[1-4094]：</TD>
                                    <TD colspan='2'><INPUT id=MulticastVID maxLength=4 size=5 name=MulticastVID value="">
                                      <input type="hidden" name="MulVIDUsed" value="No"></TD>
                                  </TR>
                                  <TR id='MTUsec'>
                                    <TD id='MIUDescrip'>MTU[1-1500]：</TD>
                                    <TD colspan='2'><INPUT id=MTU maxLength=4 size=5 name=MTU value="1500"></TD>
                                  </TR>
                                </TBODY>
                              </TABLE>
                              <DIV id=secNat>
                                <TABLE cellSpacing=0 cellPadding=0 width="100%" border=0>
                                  <TBODY>
                                    <TR>
                                      <TD width=150>使能NAT：</TD>
                                      <TD><LABEL>
                                          <INPUT id=cb_nat type=checkbox name=cb_nat onClick="EnableNatClick()" checked>
                                          <INPUT id=nat type=hidden value="Enable" name="nat">
                                        </LABEL></TD>
                                    </TR>
                                  </TBODY>
                                </TABLE>
                              </DIV>
                              <DIV id=secIgmp>
                                <TABLE cellSpacing=0 cellPadding=0 width="100%" border=0>
                                  <TBODY>
                                    <TR style="DISPLAY: none">
                                      <TD width=150>使能IGMP Proxy：</TD>
                                      <TD><LABEL>
                                          <INPUT id=cb_enblIgmp type=checkbox name="cb_enblIgmp" >
                                          <INPUT id=enblIgmp type=hidden value="No" name=enblIgmp>
                                        </LABEL></TD>
                                    </TR>
                                  </TBODY>
                                </TABLE>
                              </DIV>
                              <BR>
                              <DIV id=secRouteItems>
                                <DIV id=secStaticItems style="DISPLAY: none">
                                  <TABLE cellSpacing=0 cellPadding=0 width="100%" border=0>
                                    <TBODY>
                                      <TR>
                                        <TD width=150>IP 地址：</TD>
                                        <TD><LABEL>
                                            <INPUT id=wanIpAddress maxLength=15 size=15 name=wanIpAddress value="">
                                          </LABEL></TD>
                                      </TR>
                                      <TR>
                                        <TD>子网掩码：</TD>
                                        <TD><INPUT id=wanSubnetMask maxLength=15 size=15 name=wanSubnetMask value=""></TD>
                                      </TR>
                                      <TR>
                                        <TD>缺省网关：</TD>
                                        <TD><INPUT id=defaultGateway maxLength=15 size=15 name=defaultGateway value=""></TD>
                                      </TR>
                                      <TR>
                                        <TD>首选DNS服务器：</TD>
                                        <TD><INPUT id=dnsPrimary maxLength=15 size=15 name=dnsPrimary value=""></TD>
                                      </TR>
                                      <TR>
                                        <TD>备用DNS服务器：</TD>
                                        <TD><INPUT id=dnsSecondary maxLength=15 size=15 name=dnsSecondary value=""></TD>
                                      </TR>
                                    </TBODY>
                                  </TABLE>
                                </DIV>
                                <DIV id=secPppoeItems>
                                  <TABLE cellSpacing=0 cellPadding=0 width="100%" border=0>
                                    <TBODY>
                                      <TR>
                                        <TD width=150>用户名：</TD>
                                        <TD><LABEL>
                                            <INPUT id='pppUserName' style="FONT-FAMILY: '宋体', '宋体'; width:120px;" maxLength=63 size=15 name='pppUserName' value="">
                                          </LABEL></TD>
                                      </TR>
                                      <TR>
                                        <TD>密码：</TD>
                                        <TD><span id="inpsw">
                                          <INPUT id=pppPassword style="FONT-FAMILY: 'MicrosoftYaHei', 'Microsoft YaHei'; width:120px;" type=password maxLength=63 size=15 name=pppPassword value="">
                                          </span>
                                          </TD>
                                      </TR>
                                      <TR >
                                        <TD>服务名称：</TD>
                                        <TD><INPUT id=pppServiceName style="FONT-FAMILY: 'MicrosoftYaHei', 'Microsoft YaHei'; width:120px;"  maxLength=63 size=15 name=pppServiceName></TD>
                                      </TR>
                                      
                                      
                                      <TR <%checkWrite("web_pppoe_type_enable")%> >
                                        <TD>拨号方式：</TD>
                                        <TD><SELECT id=DialMethod style="WIDTH: 117px" onchange=DialMethodChange() name=DialMethod>
                                          <option value="Auto" selected>自动拨号
                                          <option value="OnDemand">按需拨号
										  <option value="Manual" >手动拨号
                                          </SELECT></TD>
                                      </TR>  
                                      <TR id=secManualDial style="DISPLAY: none" >
                                        <TD>&nbsp;</TD>
                                        <TD>
											<INPUT id=pppDialButton onclick=ManualConnectSubmit() type=button value=拨号 name=pppDialButton>
											<INPUT id=pppLinkDownButton onclick=ManualDisconnectSubmit() type=button value=断开 name=pppLinkDownButton>
										</TD>
                                      </TR>
                                      <TR id=secIdleTime style="DISPLAY: none" >
                                        <TD>
                                          空闲超时（分钟）[1-4320]
                                          </TD>
                                        <TD><INPUT id=pppTimeOut maxLength=4 size=4 name=pppTimeOut>
                                          <input type="hidden" name="pppv6Mode" value="0"></TD>
                                      </TR>
                                      
                                      <TR id='ppp_bi'>
                                        <TD width=150>PPPoE路由桥混合模式启用：</TD>
                                        <TD><INPUT id='cb_enable_pppbi' type=checkbox name='cb_enable_pppbi' >
                                          <INPUT id='enablepppbi' type=hidden name='enablepppbi'>
                                          <INPUT id='pppbiUsed' type=hidden name='pppbiUsed'>
                                          <INPUT id='pppbiDisabled' type=hidden name='pppbiDisabled' value='No'></TD>
										  <INPUT type=hidden id='encodePppUserName' name='encodePppUserName' value="">
										  <INPUT type=hidden id='encodePppPassword' name='encodePppPassword' value="">												  
                                      </TR>
                                      
                                    </TBODY>
                                  </TABLE>
                                </DIV>
                              </DIV>
                              <DIV id=secIPv6Div>
                                <TABLE cellSpacing=0 cellPadding=0 width="100%" border=0>
                                  <TBODY>
                                    <TR id=TrIpv6AddrType>
                                      <TD width=150>IPv6 WAN信息获取方式:</TD>
                                      <TD><select id="IdIpv6AddrType" style="WIDTH: 130px" onChange="pdDefaultSel=1;OnIPv6Changed();" name="IdIpv6AddrType">
                                          <option value="SLAAC" >SLAAC
                                          <option value="DHCP" >DHCP
                                          <option value="Static" selected>Static
                                        </select></TD>
                                    </TR>
                                    <TR id=TrIpv6Addr>
                                      <TD>IPv6地址:</TD>
                                      <TD><INPUT id=IdIpv6Addr maxLength=39 size=36 name=IdIpv6Addr value="">
                                        &nbsp;/
                                        <INPUT id=IdIpv6PrefixLen maxLength=3 size=3 name=IdIpv6PrefixLen value=""></TD>
                                    </TR>
                                    <TR id=TrIpv6Gateway>
                                      <TD>IPv6默认网关:</TD>
                                      <TD><INPUT id=IdIpv6Gateway maxLength=39 size=36 name=IdIpv6Gateway value=""></TD>
                                    </TR>
                                    <TR id="TrIpv6GatewayInfo">
                                      <TD></TD>
                                      <TD>(IPv6默认网关不填内容，则自动获取)</TD>
                                    </TR>
                                    <TR id=TrIpv6Dns1>
                                      <TD>IPv6首选DNS服务器:</TD>
                                      <TD><INPUT id=IdIpv6Dns1 maxLength=39 size=36 name=IdIpv6Dns1 value=""></TD>
                                    </TR>
                                    <TR id=TrIpv6Dns2>
                                      <TD>IPv6备用DNS服务器:</TD>
                                      <TD><INPUT id=IdIpv6Dns2 maxLength=39 size=36 name=IdIpv6Dns2 value=""></TD>
                                    </TR>
                                    <TR id='PDEnableSec'>
                                      <TD id='PDEnableDescrip'>PD使能：</TD>
                                      <TD><INPUT id='cb_enabledpd' type=checkbox onclick='cb_pdEnableChange()' name='cb_enabledpd' >
                                        <INPUT id='enablepd' type=hidden name='enablepd'>
                                        <INPUT id='PDUsed' type=hidden name='PDUsed'>
                                        <INPUT id='PDDisabled' type=hidden name='PDDisabled' value='No'></TD>
                                    </TR>
                                    <TR id='pdmode_1'>
                                      <TD>前缀模式：</TD>
                                      <TD><INPUT id='pdmode' onclick='pdmodeChange()' type=radio value="Yes" name="pdmode" checked>
                                        Auto&nbsp;&nbsp;
                                        <INPUT id='pdmode' onclick='pdmodeChange()' type=radio value="No" name="pdmode" >
                                        Manual&nbsp;&nbsp;
                                        <INPUT id='pdmodeUsed' type=hidden name='pdmodeUsed'>
                                        <INPUT id='pdmodeDisabled' type=hidden name='pdmodeDisabled' value='No'>
                                        <INPUT id='pdmodeAuto' type=hidden name='pdmodeAuto' value='PrefixDelegation'>
                                        <INPUT id='pdmodeStatic' type=hidden name='pdmodeStatic' value='Static'>
                                        <INPUT id='pdmodeNone' type=hidden name='pdmodeNone' value='None'></TD>
                                    </TR>
                                    <TR id='pdmode_2'>
                                      <TD>前缀地址：</TD>
                                      <TD><INPUT id='pdprefix' maxLength=39 size=36 name='pdprefix' value=""></TD>
                                    </TR>
                                    <TR id='pdmode_3'>
                                      <TD>首选寿命：</TD>
                                      <TD><INPUT id='pdprefixptime' maxLength=10 size=10 name='pdprefixptime' value="">
                                        <STRONG style="COLOR: #ff0033">*</STRONG>[600 - 4294967295 s] </TD>
                                    </TR>
                                    <TR id='pdmode_4'>
                                      <TD>有效寿命：</TD>
                                      <TD><INPUT id='pdprefixvtime' maxLength=10 size=10 name='pdprefixvtime' value="">
                                        <STRONG style="COLOR: #ff0033">*</STRONG>[600 - 4294967295 s] </TD>
                                    </TR>
                                    
                                    <TR id='dslite_1'>
                                      <TD>DS-Lite启用：</TD>
                                      <TD><INPUT id='cb_enabledslite' onclick=cb_enabledsliteChange() type=checkbox name='cb_enabledslite' >
                                        <INPUT id='enabledslite' type=hidden name='enabledslite'>
                                        <INPUT id='dsliteUsed' type=hidden name='dsliteUsed'>
                                        <INPUT id='dsliteDisabled' type=hidden name='dsliteDisabled' value='No'></TD>
                                    </TR>
                                    <TR id='dslite_2'>
                                      <TD>DS-Lite模式：</TD>
                                      <TD><INPUT id='dslitemode' onclick='dslitemodeChange()' type=radio value="0" name="dslitemode">
                                        Auto&nbsp;&nbsp;
                                        <INPUT id='dslitemode' onclick='dslitemodeChange()' type=radio value="1" name="dslitemode" >
                                        Manual&nbsp;&nbsp; </TD>
                                    </TR>
                                    <TR id='dslite_3'>
                                      <TD>DS-Lite服务器：</TD>
                                      <TD><INPUT id='dsliteaddress' maxLength=39 size=36 name='dsliteaddress' value=""></TD>
                                    </TR>
                                    
                                  </TBODY>
                                </TABLE>
                              </DIV>
                              
                      
                          </TR>
                          <TR>
                            <TD><INPUT id=pppIdleTimeout type=hidden value=0 name=pppIdleTimeout>
								<INPUT type=hidden name=xponstate value="Yes"></TD>
                          </TR>
                        </TBODY>
                      </TABLE>
						<input type="hidden" name="submit-url" value="/net_eth_links_cmcc.asp">			
                    </FORM></TD>
                </TR>
              </TBODY>
                </TBODY>
            </TABLE>
			
			</TD>
        </TR>
      </TABLE>
	  </DIV>
		<table style="padding-left:20px; display: inline-block;">
			<tr><td><INPUT id=btnRemoveCnt style="DISPLAY: block" onclick="btnRemoveWanCnt()" type="button" value="删除连接" class="BtnDel"></td> 
			</tr>	  
		</table>

		</TD>                              
			<TABLE>
				<TBODY>
					  <td><P align=center>
						<input type="button" id=btnOK class="btnsaveup" value="确定" onclick="btnSave();">&nbsp;&nbsp;
						<input type="button" id="btnCancel" class="btnsaveup" value="取消" onclick=onCancel()> </P></TD> 
				</TBODY>
			</TABLE>
		</TR>
    </TBODY>
</TABLE>
</BODY>
</HTML>
