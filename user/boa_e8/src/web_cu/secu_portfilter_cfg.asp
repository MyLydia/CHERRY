<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<!--ϵͳĬ��ģ��-->
<HTML>
<HEAD>
<TITLE>�˿ڹ���</TITLE>
<META http-equiv=pragma content=no-cache>
<META http-equiv=cache-control content="no-cache, must-revalidate">
<META http-equiv=content-type content="text/html; charset=gbk">
<META http-equiv=content-script-type content=text/javascript>
<!--ϵͳ����css-->
<STYLE type=text/css>
@import url(/style/default.css);
</STYLE>
<!--ϵͳ�����ű�-->
<SCRIPT language="javascript" src="common.js"></SCRIPT>
<SCRIPT language="javascript" type="text/javascript">

var cgi = new Object();
<%ipPortFilterDirConfig();%>
var prot_all = [1, 2, 4, 8];
var prot_string_all = ["IPv4oE", "PPPoE", "ARP", "IPv6oE"];
var port_filter_status = new Array();
<%initPagePortFilter();%>
 /********************************************************************
**          on document load
********************************************************************/
/******port filter*************************************/
function protocal_decode(prot)
{
	var prot_string = "";
	var first=1;
	for(var i = 0;i < prot_all.length; i++)
	{
		if(prot&prot_all[i])
		{
			if(first)
			{
				prot_string += prot_string_all[i];
				first = 0;
			}
			else prot_string += "," + prot_string_all[i];
		}
	}
	return prot_string;
}
function addline(index)
{
	var newline;
	newline = document.getElementById('port_filter_table').insertRow(-1);
	newline.nowrap = true;
	newline.vAlign = "top";
	newline.align = "center";
	newline.onclick = function(){on_choose_port(index,port_filter_status[index].prot)};
	newline.setAttribute("class","white");
	newline.setAttribute("className","white");
	newline.insertCell(-1).innerHTML = port_filter_status[index].name;
	newline.insertCell(-1).innerHTML = protocal_decode(port_filter_status[index].prot);

}
function showPortFilterTable()
{
	var num = port_filter_status.length;
	var port = port_filter_status;

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
function on_choose_port(index, prot)
{
	document.getElementById("filtered_port").value = index;
	document.getElementById("TableUrlInfo").style.display="";
	document.getElementById("port_filtered_port").innerHTML = port_filter_status[index].name;
	document.getElementById("cbIPv4oE").checked=false;
	document.getElementById("cbARP").checked=false;
	document.getElementById("cbPPPoE").checked=false;
	document.getElementById("cbIPv6oE").checked=false;
	for(var i = 0;i < prot_all.length; i++)
	{
		if(prot&prot_all[i])
{
			switch(prot_all[i])
			{
			case 1:
				document.getElementById("cbIPv4oE").checked=true;
			  break;
			case 2:
				document.getElementById("cbPPPoE").checked=true;
			  break;
  			case 4:
				document.getElementById("cbARP").checked=true;
				break;
			case 8:
				document.getElementById("cbIPv6oE").checked=true;
				break;
			default:
			}		
		}
}
}
/******port filter end*********************************/

function on_init()
{
	sji_docinit(document, cgi);
	//alert("cgi.ipfilterInEnable="+cgi.ipfilterInEnable);
	//alert("cgi.ipfilterOutEnable="+cgi.ipfilterOutEnable);
	//alert("cgi.ipfilterInAction="+cgi.ipfilterInAction);
	//alert("cgi.ipfilterOutAction="+cgi.ipfilterOutAction);	
	
	//down stream
	if(cgi.ipfilterInEnable == false)
	{
		document.getElementById("id_ipFilterInMode").style.display="none";
		form_in.ipFilterInMode[0].disabled = true;
		form_in.ipFilterInMode[1].disabled = true;
		if(cgi.ipfilterInAction == true){
			form_in.ipFilterInMode[0].checked = true;
		}
		else{
			form_in.ipFilterInMode[1].checked = true;
		}
		document.getElementById("policy_frame_in").src = "about:blank";
		document.getElementById("policy_frame_in").style.display = "none"
	}
	else
	{
		document.getElementById("id_ipFilterInMode").style.display="block";
		var surl_in = ( (cgi.ipfilterInAction == true)? "secu_portfilter_blk_in.asp" : "secu_portfilter_wht_in.asp");
		document.getElementById("policy_frame_in").src = surl_in;
		document.getElementById("policy_frame_in").style.display = "block"
		if(cgi.ipfilterInAction == true){
			form_in.ipFilterInMode[0].checked = true;
		}
		else{
			form_in.ipFilterInMode[1].checked = true;
		}
		
	}
	//upstream
	//alert(cgi.ipfilterOutEnable);
	if(cgi.ipfilterOutEnable == false)
	{
		document.getElementById("id_ipFilterOutMode").style.display="none";
		form_out.ipFilterOutMode[0].disabled = true;
		form_out.ipFilterOutMode[1].disabled = true;
		if(cgi.ipfilterOutAction == true){
			form_out.ipFilterOutMode[0].checked = true;
		}
		else{
			form_out.ipFilterOutMode[1].checked = true;			
		}
		document.getElementById("policy_frame_out").src = "about:blank";
		document.getElementById("policy_frame_out").style.display = "none"
	}
	else
	{
		document.getElementById("id_ipFilterOutMode").style.display="block";
		var surl_out = ( (cgi.ipfilterOutAction == true)? "secu_portfilter_blk_out.asp" : "secu_portfilter_wht_out.asp");
		document.getElementById("policy_frame_out").src = surl_out;
		document.getElementById("policy_frame_out").style.display = "block"
		if(cgi.ipfilterOutAction == true){
			form_out.ipFilterOutMode[0].checked = true;
		}
		else{
			form_out.ipFilterOutMode[1].checked = true;			
		}		
	}
	showPortFilterTable();
}

function on_action_in(act)
{
	form_in.action.value = act;
	var cur_ipfilterInEnable = 0;
	var cur_ipFilterInMode = 0;
	//cur_ipFilterInMode = (form_in.ipFilterInMode.value == "on") ? 1:0;
	cur_ipFilterInMode = (form_in.ipFilterInMode[0].checked) ? 1:0;
	//alert("cur_ipFilterInMode="+cur_ipFilterInMode);	
    cur_ipfilterInEnable =  (form_in.ipfilterInEnable.checked) ? 1:0;
	//alert("cur_ipfilterInEnable="+cur_ipfilterInEnable);
	if(act == "sw" ){
		if(cur_ipfilterInEnable == 0){
			if(!confirm("�Ƿ�������ж˿ڹ��ˣ�")){
				form_in.ipfilterInEnable.checked = 1-cur_ipfilterInEnable;
				return;
			}
		}
		else{
			if(!confirm("�Ƿ��������ж˿ڹ��ˣ�")){
				form_in.ipfilterInEnable.checked = 1-cur_ipfilterInEnable;
				return;
			}
		}
	}

	if(act == "swmode" ){
		if(cur_ipFilterInMode == 0){
			if(!confirm("�ı����ģʽ���л����й��˹������Ƿ����Ҫ�ı����ģʽΪ��������")){
				if(cgi.ipfilterInAction == true){
					form_in.ipFilterInMode[0].checked = true;
					}
				else{
					form_in.ipFilterInMode[1].checked = true;
				}
				return;
			}
		}
		else{
			if(!confirm("�ı����ģʽ���л����й��˹������Ƿ����Ҫ�ı����ģʽΪ��������")){
				if(cgi.ipfilterInAction == true){
					form_in.ipFilterInMode[0].checked = true;
					}
				else{
					form_in.ipFilterInMode[1].checked = true;
				}
				return;
			}
		}
	}
	
	if(cur_ipfilterInEnable == 0)
	{
		if(cur_ipFilterInMode)
			form_in.ipFilterInMode[0].checked = true;
		else
			form_in.ipFilterInMode[1].checked = true;
		policy_frame_in.src = "about:blank";		
	}else{
		form_in.ipFilterInMode[0].disabled = false;
		form_in.ipFilterInMode[1].disabled = false;
		if(cur_ipFilterInMode)
			form_in.ipFilterInMode[0].checked = true;
		else
			form_in.ipFilterInMode[1].checked = true;	
		var surl_in = ( (form_in.ipFilterInMode[0].checked == true)? "secu_portfilter_blk_in.asp" : "secu_portfilter_wht_in.asp");

	}
	with(form_in)
	{
		submit();
	}
}

function on_action_out(act)
{
	form_out.action.value = act;
	var cur_ipfilterOutEnable = 0;
	var cur_ipFilterOutMode = 0;
	//cur_ipFilterOutMode = (form_out.ipFilterOutMode.value == "on") ? 1:0;
	cur_ipFilterOutMode = (form_out.ipFilterOutMode[0].checked) ? 1:0;
	//alert(cur_ipFilterOutMode);
	//alert("cur_ipFilterOutMode="+cur_ipFilterOutMode);	
	cur_ipfilterOutEnable = (form_out.ipfilterOutEnable.checked) ? 1:0;
	//alert("cur_ipfilterOutEnable="+cur_ipfilterOutEnable);	
	//alert(cur_ipfilterOutEnable);
	if(act == "sw" ){
		if(cur_ipfilterOutEnable == 0){
			if(!confirm("�Ƿ�������ж˿ڹ��ˣ�")){
				form_out.ipfilterOutEnable.checked = 1-cur_ipfilterOutEnable;
				return;
			}
		}
		else{
			if(!confirm("�Ƿ��������ж˿ڹ��ˣ�")){
				form_out.ipfilterOutEnable.checked = 1-cur_ipfilterOutEnable;
				return;
			}
		}
	}

	if(act == "swmode" )
	{
		if(cur_ipFilterOutMode == 0){
			if(!confirm("�ı����ģʽ���л����й��˹������Ƿ����Ҫ�ı����ģʽΪ��������")){
				if(cgi.ipfilterOutAction == true){
					form_out.ipFilterOutMode[0].checked = true;
					}
				else{
					form_out.ipFilterOutMode[1].checked = true;
				}
				return;
			}
		}
		else{
			if(!confirm("�ı����ģʽ���л����й��˹������Ƿ����Ҫ�ı����ģʽΪ��������")){
				if(cgi.ipfilterOutAction == true){
					form_out.ipFilterOutMode[0].checked = true;
					}
				else{
					form_out.ipFilterOutMode[1].checked = true;
				}
				return;
			}
		}
	}
	
	if(cur_ipfilterOutEnable == 0)
	{
		if(cur_ipFilterOutMode)
			form_out.ipFilterOutMode[0].checked = true;
		else
			form_out.ipFilterOutMode[1].checked = true;
	}else{
		form_out.ipFilterOutMode[0].disabled = false;
		form_out.ipFilterOutMode[1].disabled = false;
		if(cur_ipFilterOutMode)
			form_out.ipFilterOutMode[0].checked = true;
		else
			form_out.ipFilterOutMode[1].checked = true;		
		var surl_out = ( (form_out.ipFilterOutMode[0].checked == true)? "secu_portfilter_blk_out.asp" : "secu_portfilter_wht_out.asp");
	}
	with(form_out)
	{
		submit();
	}
}
function on_action_port(act){
	form_port.action.value = act;
	with(form_port)
	{
		submit();
	}
}

function on_mode_in()
{
	var surl_in = ( (form_in.ipFilterInMode[0].checked == true)? "secu_portfilter_blk_in.asp" : "secu_portfilter_wht_in.asp");
	policy_frame_in.src = surl_in;
	policy_frame_in.style.display = "block"
	with(form_in)
	{
		submit();
	}	
}

function on_mode_out()
{
	var surl_out = ( (form_out.ipFilterOutMode[0].checked == true)? "secu_portfilter_blk_out.asp" : "secu_portfilter_wht_out.asp");
	policy_frame_out.src = surl_out;
	policy_frame_out.style.display = "block"
	with(form_out)
	{
		submit();
	}
}


</SCRIPT>
</HEAD>
<!-------------------------------------------------------------------------------------->
<!--��ҳ����-->
<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000" onLoad="on_init();">
	<blockquote>
		<DIV align="left" style="padding-left:20px; padding-top:5px">
			<form id="form_out" action=/boaform/admin/formPortFilterOut method=POST name="form_out">
				<!--<b>�˿ڹ��� -- ������������ 16������.</b><br><br>-->
				<!--
				<div id="rstip" style="display:none;"><font color="red">��ʾ����ҳ������ã���Ҫ����·����������Ч��</font><br></div>
				-->
				<hr align="left" class="sep" size="1" width="90%">
				<table border="0" cellpadding="2" cellspacing="0">
					<tr>
						<td>�������еĶ˿ڹ��˹���  ʹ��:</td>
						<td><input type="checkbox" name="ipfilterOutEnable" onClick="on_action_out('sw')"></td>
						<!--
						<td>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<font color="red"><b>ע����Internet���Ӳ������ã�</b></font></td>
						-->
					</tr>
					<tr id="id_ipFilterOutMode">
						<td>����ģʽ:</td>
						<td>
						<input type="radio" name="ipFilterOutMode" value="on" onClick="on_action_out('swmode')" checked>&nbsp;&nbsp;������
						<input type="radio" name="ipFilterOutMode" value="off" onClick="on_action_out('swmode')">&nbsp;&nbsp;������
						</td>
						<!--<td>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<font color="red"><b>ע���ڰ�������ͬʱ�����ģ�</b></font></td>-->
					</tr>
				</table>
				<br>
				<input type="hidden" id="action" name="action" value="sw">
				<input type="hidden" name="submit-url" value="/secu_portfilter_cfg.asp" >
			</form>
		</div>
	</blockquote>
	<iframe src="about:blank" id="policy_frame_out" width="90%" frameborder="0" style="border-style:none; height:30%"  scrolling="auto"></iframe>
	<blockquote>
		<DIV align="left" style="padding-left:20px; padding-top:5px">
			<form id="form_in" action=/boaform/admin/formPortFilterIn method=POST name="form_in">
				<!--<b>�˿ڹ��� -- ������������ 16������.</b><br><br>-->
				<!--
				<div id="rstip" style="display:none;"><font color="red">��ʾ����ҳ������ã���Ҫ����·����������Ч��</font><br></div>
				-->
				<hr align="left" class="sep" size="1" width="90%">
				<table border="0" cellpadding="2" cellspacing="0">
					<tr>
						<td>�������еĶ˿ڹ��˹���  ʹ��:</td>
						<td><input type="checkbox" name="ipfilterInEnable" onClick="on_action_in('sw')"></td>
						<!--
						<td><input type="radio" name="ipfilterInEnable" value="off" onClick="on_action_in('sw')">&nbsp;&nbsp;����</td>
						<td><input type="radio" name="ipfilterInEnable" value="on" onClick="on_action_in('sw')">&nbsp;&nbsp;����</td>
						-->
						<!--
						<td>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<font color="red"><b>ע����Internet���Ӳ������ã�</b></font></td>
						-->
					</tr>
					<tr id="id_ipFilterInMode">
						<td>����ģʽ:</td>
						<td>
						<input type="radio" name="ipFilterInMode" value="on" onClick="on_action_in('swmode')" checked>&nbsp;&nbsp;������
						<input type="radio" name="ipFilterInMode" value="off" onClick="on_action_in('swmode')">&nbsp;&nbsp;������
						</td>
						<!--<td>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<font color="red"><b>ע���ڰ�������ͬʱ�����ģ�</b></font></td>-->
					</tr>					
				</table>
				<br>
				<input type="hidden" id="action" name="action" value="sw">
				<input type="hidden" name="submit-url" value="/secu_portfilter_cfg.asp" >
			</form>
		</div>
	</blockquote>	
	<iframe src="about:blank" id="policy_frame_in" width="90%" frameborder="0" style="border-style:none; height:30%"  scrolling="auto"></iframe>	
	<blockquote>
		<DIV align="left" style="padding-left:20px; padding-top:5px">
			<form id="form_port" action=/boaform/admin/formPortFilterPort method=POST name="form_port">
				<hr align="left" class="sep" size="1" width="90%">
				<table id="port_filter_table" class="table1_bg" width="100%" border="1">
					<tr>
						<td width="10%">�˿�</td>
						<td width="90%">���˵�Э��</td>
					</tr>
				</table>
				<div id="TableUrlInfo" style="display:none">
					<table class="table1_bg" width="100%" border="1">
						<tr>
							<td width="25%">�˿�</td>
							<td width="75%" id="port_filtered_port"></td>
						</tr>
						<tr>
							<td width="25%">Э��</td>
							<td width="75%" id="port_filtered_portocal">
								<input id="cbIPv4oE" name="cbIPv4oE" type="checkbox">IPv4oE
								<input id="cbPPPoE" name="cbPPPoE" type="checkbox">PPPoE
								<input id="cbARP" name="cbARP" type="checkbox">ARP
								<input id="cbIPv6oE" name="cbIPv6oE" type="checkbox">IPv6oE
							</td>
						</tr>
					</table>
					<br>
					<p align="center">
					<!--
					<input type="button" class="btnsaveup" name="clrrec" onClick="on_action_port('apply');" value="Ӧ��">
					<input type="button" class="BtnCnl" name="saverec" onClick="on_action_port('cancel');" value="ȡ��">
					-->
					<button class="btnsaveup" name="clrrec" onClick="on_action_port('apply');">Ӧ��</button>
					<button class="BtnCnl" name="saverec" onClick="on_action_port('cancel');">ȡ��</button>
					</p>
				</div>
				<input type="hidden" id="filtered_port" name="filtered_port">
				<input type="hidden" id="action" name="action">
				<input type="hidden" name="submit-url" value="/secu_portfilter_cfg.asp" >
			</form>
		</div>
	</blockquote>
</body>
<%addHttpNoCache();%>
</html>
