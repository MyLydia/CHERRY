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
</SCRIPT>

<STYLE type=text/css>
@import url(/style/default.css);
</STYLE>
</head>

<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000">
<blockquote>
<DIV align="left" style="padding-left:20px; padding-top:5px">
  <table cellpadding="0px" cellspacing="2px">
  <tr>
      <td width="150px">API </td>
      <td width="150px">API function name</td>
	  <td width="500px">API result</td>
  </tr>
  <tr>
      <td width="150px">SER </td>
      <td width="150px">getSER</td>
	  <td width="500px"><% showSER(); %></td>
  </tr>
  <tr>
      <td width="150px">ErrorCode </td>
      <td width="150px">getErrorCode</td>
	  <td width="500px"><% showErrorCode(); %></td>
  </tr>
  <tr>
      <td width="150px">PLR </td>
      <td width="150px">getPLR</td>
	  <td width="500px"><% showPLR(); %></td>
  </tr>
  <tr>
      <td width="150px">PacketLost </td>
      <td width="150px">getPacketLost</td>
	  <td width="500px"><% showPacketLost(); %></td>
  </tr>
  <tr>
      <td width="150px">RegisterNumberITMS </td>
      <td width="150px">getRegisterNumberITMS</td>
	  <td width="500px"><% showRegisterNumberITMS(); %></td>
  </tr>
  <tr>
      <td width="150px">RegisterSuccNumITMS </td>
      <td width="150px">getRegisterSuccNumITMS</td>
	  <td width="500px"><% showRegisterSuccNumITMS(); %></td>
  </tr>
<tr>
      <td width="150px">LANxWorkBandwidth </td>
      <td width="150px">getLANxWorkBandwidth</td>
	  <td width="500px"><% showLANxWorkBandwidth(); %></td>
  </tr>
  <tr>
      <td width="150px">LANxState </td>
      <td width="150px">getLANxState</td>
	  <td width="500px"><% showLANxState(); %></td>
  </tr>
  <tr>
      <td width="150px">UpData </td>
      <td width="150px">getUpData</td>
	  <td width="500px"><% showUpData(); %></td>
  </tr>
  <tr>
	  <td width="150px">DownData </td>
      <td width="150px">getDownData</td>
	  <td width="500px"><% showDownData(); %></td>
  </tr>
  <tr>
      <td width="150px">AllDeviceNumber </td>
      <td width="150px">getAllDeviceNumber</td>
	  <td width="500px"><% showAllDeviceNumber(); %></td>
  </tr>
  <tr>
      <td width="150px">WLANDeviceMAC </td>
      <td width="150px">getWLANDeviceMAC</td>
	  <td width="500px"><% showWLANDeviceMAC(); %></td>
  </tr>
  <tr>
      <td width="150px">LANDeviceMAC </td>
      <td width="150px">getLANDeviceMAC</td>
	  <td width="500px"><% showLANDeviceMAC(); %></td>
  </tr>
  <tr>
      <td width="150px">DevicePacketLoss </td>
      <td width="150px">getDevicePacketLoss</td>
	  <td width="500px"><% showDevicePacketLoss(); %></td>
  </tr>
  <tr>
      <td width="150px">DHCPRegisterNumber</td>
      <td width="150px">getDHCPRegisterNumber</td>
	  <td width="500px"><% showDHCPRegisterNumber(); %></td>
  </tr>
  <tr>
      <td width="150px">DHCPSuccessNumber</td>
      <td width="150px">getDHCPSuccessNumber</td>
	  <td width="500px"><% showDHCPSuccessNumber(); %></td>
  </tr>
  <tr>
      <td width="150px">CPURate</td>
      <td width="150px">getCPURate</td>
	  <td width="500px"><%showCPURate(); %></td>
  </tr>
  <tr>
      <td width="150px">MemRate</td>
      <td width="150px">getMemRate</td>
	  <td width="500px"><%showMemRate(); %></td>
  </tr>
  <tr>
      <td width="150px">DevicePacketLoss </td>
      <td width="150px">getDevicePacketLoss</td>
	  <td width="500px"><% showDevicePacketLoss(); %></td>
  </tr>
  <tr>
      <td width="150px">VoiceInfo </td>
      <td width="150px">getVoiceInfo</td>
	 <% asp_voip_e8c_getInfo("voice_info"); %>
  </tr>
  <tr>
      <td width="150px">VoiceState </td>
      <td width="150px">getVoiceState</td>
	  <% asp_voip_e8c_getState("voice_state"); %>
  </tr>
  <tr>
      <td width="150px">TEMP </td>
      <td width="150px">getTEMP</td>
	  <td width="500px"><% showTEMP(); %></td>
  </tr>  
  <tr>
      <td width="150px">OpticalInPower </td>
      <td width="150px">getOpticalInPower</td>
	  <td width="500px"><% showOpticalInPower(); %></td>
  </tr>
  <tr>
      <td width="150px">OpticalOutPower </td>
      <td width="150px">getOpticalOutPower</td>
	  <td width="500px"><% showOpticalOutPower(); %></td>
  </tr>
  <tr>
      <td width="150px">RoutingMode </td>
      <td width="150px">getRoutingMode</td>
	  <td width="500px"><% showRoutingMode(); %></td>
  </tr>
  <tr>
      <td width="150px">RegisterOLTNumber </td>
      <td width="150px">getRegisterOLTNumber</td>
	  <td width="500px"><% showRegisterOLTNumber(); %></td>
  </tr>  
  <tr>
      <td width="150px">RegisterOLTSuccNumber </td>
      <td width="150px">getRegisterOLTSuccNumber</td>
	  <td width="500px"><% showRegisterOLTSuccNumber(); %></td>
  </tr>
  <tr>
      <td width="150px">MulticastNumber </td>
      <td width="150px">getMulticastNumber</td>
	  <td width="500px"><% showMulticastNumber(); %></td>
  </tr>
  </table>
</DIV>
</body>
</html>
