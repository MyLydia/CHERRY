<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<!--系统默认模板-->
<HTML>
<HEAD>
<TITLE>Version Information Setup</TITLE>
<META http-equiv=pragma content=no-cache>
<META http-equiv=cache-control content="no-cache, must-revalidate">
<META http-equiv=content-type content="text/html; charset=gbk">
<META http-equiv=content-script-type content=text/javascript>
<!--系统公共css-->
<STYLE type=text/css>
@import url(../style/default.css);
</STYLE>
<!--系统公共脚本-->
<SCRIPT language="javascript" src="../common.js"></SCRIPT>
<script type="text/javascript" src="../share.js" charset="gbk"></script>
<SCRIPT language="javascript" type="text/javascript">
function sendClicked()
{
    if (document.password.binary.value=="") {
        alert('选择的档案不能为空!'); //Selected file cannot be empty!
        document.password.binary.focus();
        return false;
    }

    if (!confirm('您确定要更新此软件?')) //Do you really want to upgrade the firmware?
        return false;
		
    return true;
}


function uploadClick()
{		
   	if (document.saveConfig.binary.value.length == 0) {
		alert('请选择档案!'); //Choose File!
		document.saveConfig.binary.focus();
		return false;
	}
	
	return true;
}

function disableRegClick()
{
	postTableEncrypt(document.disable_register.postSecurityFlag, document.disable_register);
	
	return true;
}

function disableLimitClick()
{
	postTableEncrypt(document.disable_wanlimit.postSecurityFlag, document.disable_wanlimit);
	
	return true;
}

function exportClick()
{		
   	postTableEncrypt(document.exportOMCIlog.postSecurityFlag, document.exportOMCIlog);
	alert('请等待60秒!'); //Please waiting for 60 seconds!

	return true;
}

function onClickTelnetEnable()
{
	postTableEncrypt(document.telnetEnable.postSecurityFlag, document.telnetEnable);
	document.telnetEnable.submit();
}

function onClickMirrorEnable()
{
	postTableEncrypt(document.pktmirrorEnable.postSecurityFlag, document.pktmirrorEnable);
	document.pktmirrorEnable.submit();
}

function saveChanges()
{
	postTableEncrypt(document.vermod.postSecurityFlag, document.vermod);
	return true;
}

function on_action(act)
{
	if (act == 'ping_wan')
	{
		postTableEncrypt(document.ping_wan.postSecurityFlag, document.ping_wan);
		document.ping_wan.submit();
		return true;
	}
	else if (act == 'voip_dbg')
	{
		postTableEncrypt(document.voip_dbg.postSecurityFlag, document.voip_dbg);
		document.voip_dbg.submit();
		return true;
	}
	else if (act == 'ring_vol')
	{
		postTableEncrypt(document.ring_vol.postSecurityFlag, document.ring_vol);
		document.ring_vol.submit();
		return true;
	}
	else
		return false;
}

</SCRIPT>

<STYLE type=text/css>
@import url(/style/default.css);
</STYLE>
</head>

<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000">
<blockquote>
<DIV align="left" style="padding-left:20px; padding-top:5px">

<form action=/boaform/formVersionMod method=POST name="vermod">
	<h2><font color="#0000FF">Version</font></h2>
  
  <table cellpadding="0px" cellspacing="2px">


  <tr>
      <td width="150px">Manufacturer:</td>
      <td><input type="text" name="txt_mft" size="50" maxlength="50" value=<% getInfo("rtk_manufacturer"); %>>(ZTE)</td>
  </tr>

  <tr>
      <td width="150px">OUI:</td>
      <td><input type="text" name="txt_oui" size="50" maxlength="50" value=<% getInfo("rtk_oui"); %>>(5422F8)</td>
  </tr>

  <tr>
      <td width="150px">Product Class:</td>
      <td><input type="text" name="txt_proclass" size="50" maxlength="50" value=<% getInfo("rtk_productclass"); %>>(F660)</td>
  </tr>
    <tr>
      <td width="150px">Hardware Serial Number:</td>
      <td><input type="text" name="txt_serialno" size="50" maxlength="50" value=<% getInfo("rtk_serialno"); %>>(000000000002)</td>
  </tr>
    <tr>
      <td width="150px">Provisioning Code:</td>
      <td><input type="text" name="txt_provisioningcode" size="50" maxlength="50" value=<% getInfo("cwmp_provisioningcode"); %>>(TLCO.GRP2)</td>
  </tr>
  <tr>
      <td width="150px">Spec. Version</td>
      <td><input type="text" name="txt_specver" size="50" maxlength="50" value=<% getInfo("rtk_specver"); %>>(1.0)</td>
  </tr>
  
  <tr>
      <td width="150px">SoftwareVersion</td>
      <td><input type="text" name="txt_swver" size="50" maxlength="50" value=<% getInfo("rtk_swver"); %>>(V2.30.10P16T2S)</td>
  </tr>
  
  <tr>
      <td width="150px">Hardware Version</td>
      <td><input type="text" name="txt_hwver" size="50" maxlength="50" value=<% getInfo("rtk_hwver"); %>>(V3.0)</td>
  </tr>
  <tr>
      <td width="150px">GPON Serial Number</td>
      <td><input type="text" name="txt_gponsn" size="13" maxlength="13" value=<% getInfo("gpon_sn"); %>></td>
  </tr>
   <tr>
      <td width="150px">ELAN MAC Address</td>
      <td><input type="text" name="txt_elanmac" size="12" maxlength="12" value=<% getInfo("elan_mac_addr"); %>></td>
  </tr>
     <tr>
      <td width="250px">公网接入人数限制(0為取消)</td>
      <td><input type="text" name="txt_wanlimit" size="12" maxlength="12" value=<% getInfo("wan_limit"); %>></td>
  </tr>
     <tr>
      <td width="250px">LOID注册状态(0為成功,1~3為失败,4為注册超时,5為已注册)</td>
      <td><input type="text" name="txt_reg_status" size="12" maxlength="12" value=<% getInfo("loid_reg_status"); %>></td>
  </tr>
       <tr>
      <td width="250px">LOID下发业务結果(1為下发成功,2為下发失败)</td>
      <td><input type="text" name="txt_reg_result" size="12" maxlength="12" value=<% getInfo("loid_reg_result"); %>></td>
  </tr>
   </tr>
       <tr>
      <td width="250px">启用UI可设定项目(tr069 WAN/Conf)(0為锁定,1為启用)</td>
      <td><input type="text" name="txt_cwmp_conf" size="12" maxlength="12" value=<% getInfo("cwmp_conf"); %>></td>
  </tr>
 </table>

      <input type="submit" value="Save" onClick="return saveChanges()">&nbsp;&nbsp;
      <!--input type="reset" value="Undo" name="reset" onClick="resetClick()"-->
      <input type="hidden" value="/bd/vermod.asp" name="submit-url">
      <input type="hidden" name="postSecurityFlag" value="">



 </form>
 </DIV>
</blockquote>
<blockquote>
<DIV align="left" style="padding-left:20px; padding-top:5px">
<h2><font color="#0000FF">Firmware Upgrade</font></h2>

<form action=/boaform/admin/formUpload method=POST enctype="multipart/form-data" name="password">
<table border="0" cellspacing="4" width="500">
 <tr><td><font size=2>
 您可以使用本页面为设备升级一个新的软件版本。请注意，在升级过程中请不要断电，这样可能会使系统崩溃 <!--This page allows you upgrade the firmware to the newer version. Please note that do not power off the device during the upload because this make the system unbootable. --> </font></td></tr>
 <tr><td><hr size=1 noshade align=top></td></tr>
</table>
<table border="0" cellspacing="4" width="500">
  <tr>
      <td><font size=2><input type="file" value="Choose File" name="binary" size=20></td>
  </tr>
  </table>
    <p> <input type="submit" value="Upgrade"  onclick="return sendClicked()">&nbsp;&nbsp;
        <input type="reset" value="Reset" name="reset">
    </p>
 </form>
  </DIV>
 </blockquote>

<blockquote>
<DIV align="left" style="padding-left:20px; padding-top:5px">
<h2><font color="#0000FF">OMCI</font></h2>
  <form action=/boaform/formExportOMCIlog method=POST name="exportOMCIlog">
  <tr>
    <td width="40%"><font size=2><b>Export:</b></font></td>
    <td width="30%"><font size=2>
      <input type="submit" value="Export"  onclick="return exportClick()">
      <input type="hidden" name="postSecurityFlag" value="">
    </td>
    </font></tr>
  </form>

</DIV>
</blockquote>

 <blockquote>
<DIV align="left" style="padding-left:20px; padding-top:5px">
  <form action=/boaform/formImportOMCIShell enctype="multipart/form-data" method=POST name="saveConfig">
  <tr>
    <td width="40%"><font size=2><b>Import:</b></font></td>
    <td width="30%"><font size=2><input type="file" value="Choose File" name="binary" size=24></font></td>
    <td width="20%"><font size=2><input type="submit" value="Import" onclick="return uploadClick()"></font></td>
  </tr>  
  </form> 

</DIV>
</blockquote>

 <blockquote>
<DIV align="left" style="padding-left:20px; padding-top:5px">
  <form action=/boaform/formDisableLoidReg method=POST name="disable_register">
  <tr>
    <td width="40%"><font size=2><b>取消LOID注册弹出及网页重导入限制</b></font></td>
    <td width="20%"><font size=2><input type="submit" value="取消" onclick="return disableRegClick()"></font></td>
    <input type="hidden" name="postSecurityFlag" value="">
  </tr>  
  </form> 

</DIV>
</blockquote>

 <blockquote>
<DIV align="left" style="padding-left:20px; padding-top:5px">
  <form action=/boaform/formDisableWanLimit method=POST name="disable_wanlimit">
  <tr>
    <td width="40%"><font size=2><b>取消公网接入人数限制</b></font></td>
    <td width="20%"><font size=2><input type="submit" value="取消" onclick="return disableLimitClick()"></font></td>
    <input type="hidden" name="postSecurityFlag" value="">
  </tr>  
  </form> 

</DIV>
</blockquote>
<blockquote>
<DIV align="left" style="padding-left:20px; padding-top:5px">
	<h2><font color="#0000FF">Telnet 配置</font></h2>(临时配置，重启后失效)
	<form action=/boaform/formTelnetEnable method=POST name="telnetEnable">
		<table border="0" cellspacing="4" width="500">
			<tr><td>
				<input type="radio" value="0" name="telneten" <% checkWrite("telnetenable0"); %> onClick="onClickTelnetEnable()">disable&nbsp;&nbsp;
     			<input type="radio" value="1" name="telneten" <% checkWrite("telnetenable1"); %> onClick="onClickTelnetEnable()">enable
				<input type="radio" value="2" name="telneten" <% checkWrite("telnetenable2"); %> onClick="onClickTelnetEnable()">enable(永久开启)
			</td></tr>
			<input type="hidden" value="/bd/vermod.asp" name="submit-url">
			<input type="hidden" name="postSecurityFlag" value="">
		</table>
	</form>
</DIV>
</blockquote>
<blockquote>
<DIV align="left" style="padding-left:20px; padding-top:5px">
	<h2><font color="#0000FF">端口鏡像配置，网线接LAN1口</font></h2>(临时配置，重启后失效)
	<form action=/boaform/formpktmirrorEnable method=POST name="pktmirrorEnable">
		<table border="0" cellspacing="4" width="500">
			<tr><td>
     			<input type="radio" value="0" name="pktmirroren"  onClick="onClickMirrorEnable()">鏡像PON口
				<input type="radio" value="1" name="pktmirroren" onClick="onClickMirrorEnable()">鏡像PON及CPU口
			</td></tr>
			<input type="hidden" value="/bd/vermod.asp" name="submit-url">
			<input type="hidden" name="postSecurityFlag" value="">
		</table>
	</form>
</DIV>
</blockquote>
<blockquote>
<DIV align="left" style="padding-left:20px; padding-top:5px">
  <h2><font color="#0000FF">允许外网ping WAN口</font></h2>(临时配置，重启后失效)
  <form action=/boaform/formPingWAN method=POST name="ping_wan">
    <table border="0" cellspacing="4" width="500">
      <tr><td>
        <input type="checkbox" <% checkWrite("enable_ping_wan"); %> name="ping_wan" onClick="on_action('ping_wan')"> 开启
      </td></tr>
      <input type="hidden" value="/bd/vermod.asp" name="submit-url">
      <input type="hidden" name="postSecurityFlag" value="">
    </table>
  </form>
</DIV>
</blockquote>
<blockquote>
<DIV align="left" style="padding-left:20px; padding-top:5px">
  <h2><font color="#0000FF">VoIP debug</font></h2>
  <form action=/boaform/admin/debug_e8c_set method=POST name="voip_dbg">
    <table border="0" cellspacing="4" width="500">
	<tr><td>
        <input type="checkbox" <%voip_e8c_get("sip_debug");%> name="sip_debug" onClick="on_action('voip_dbg')"> 开启
    </td></tr>
    </table>

	 <input type="hidden" value="/bd/vermod.asp" name="submit-url">
	 <input type="hidden" name="postSecurityFlag" value="">
  </form>
</DIV>
</blockquote>
<blockquote>
<DIV align="left" style="padding-left:20px; padding-top:5px">
  <h2><font color="#0000FF">振铃电压</font></h2>
  <form action=/boaform/admin/debug_e8c_set method=POST name="ring_vol">
    <table border="0" cellspacing="4" width="500">

	<tr>
		<td><select name=RingVoltage> <%voip_e8c_get("RingVoltage");%></select></td>
	</tr>
    </table>
	<input type="button" class="button" name="btnDown" value="电压启用" onClick="on_action('ring_vol')">
      <input type="hidden" value="/bd/vermod.asp" name="submit-url">
      <input type="hidden" name="postSecurityFlag" value="">
  </form>
</DIV>
</blockquote>
</body>

</html>
