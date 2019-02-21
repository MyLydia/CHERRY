<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<!--系统默认模板-->
<html>
<head>
<title>QoS 添加</title>
<META http-equiv=pragma content=no-cache>
<META http-equiv=cache-control content="no-cache, must-revalidate">
<META http-equiv=content-type content="text/html; charset=gbk">
<META http-equiv=content-script-type content=text/javascript>
<!--系统公共css-->
<style type=text/css>
@import url(/style/default.css);
</style>
<!--系统公共脚本-->
<script language="javascript" src="common.js"></script>
<script language="javascript" type="text/javascript">
var policy = 1;
var templateName = "<% checkWrite("qos_mode"); %>";
var rules = new Array();
var queues = new Array();
<% initQueuePolicy(); %>

function queue_display() {
	var hrow=lstrc.rows[0];
	var hcell=hrow.cells[1];
	
	if (document.forms[0].queuepolicy[0].checked){
		hcell.innerHTML = "优先级";
		showhide("mandatoryBW",0);
	}else{
		hcell.innerHTML = "权重(%)";
		showhide("mandatoryBW",1);
	}
	if(lstrc.rows){while(lstrc.rows.length > 1) lstrc.deleteRow(1);}
	for(var i = 0; i < queues.length; i++) {
		var row = lstrc.insertRow(i + 1);
		row.nowrap = true;
		row.vAlign = "center";
		row.align = "center";

		var cell = row.insertCell(0);
		cell.innerHTML = queues[i].qname;
		cell = row.insertCell(1);
		if (document.forms[0].queuepolicy[0].checked)
			cell.innerHTML = queues[i].prio;
		else
			cell.innerHTML = "<input type=\"text\" name=w" + i + " value=" + queues[i].weight + " size=3>";
		cell = row.insertCell(2);
		qcheck= queues[i].enable? " checked":"";
		cell.innerHTML = "<input type=\"checkbox\" name=qen" + i + qcheck + ">";
	}
	
}

function on_init(){
//	document.forms[0].queuepolicy[0].checked = true;
//	alert(document.forms[0].queuepolicy[0].checked );
	with(document.forms[0]){
		if(policy != 0 && policy !=1)
			policy = 0;
		queuepolicy[policy].checked = true;
		setCheck('qosen',qosEnable);
		setCheck('enable_dscp_remark',m_dscp_enable);
		setCheck('ip_qos_mandatory_bandwith_en',m_ip_qos_mandatory_bandwidth_en);
		setSelect('enable_1p_remark', m_1p_enable);		
		total_bandwidth.value = totalBandwidth;
		//qosPly.style.display = qosEnable==0 ? "":"block";
		showhide("qosPly",qosEnable);
		setSelect('template', templateName);
		QoSChangeTemplate();
		if(qosEnable){
			//qostable.style.display=up_mode?"":"block";
			//qospolicyshow.style.display=up_mode?"":"block";
			showhide("qospolicyshow",!up_mode);
			showhide("qostable",!up_mode);
		}
	}
	queue_display();
}

function on_save() {
	with(document.forms[0]) {
		var sbmtstr = "";
		if(queuepolicy[0].checked==true)
			sbmtstr = "policy=0";
		else{ //WRR策略
			sbmtstr = "policy=1";
			var weight=0;
			if(qen0.checked)
				weight+=parseInt(w0.value);
			if(qen1.checked)
				weight+=parseInt(w1.value);
			if(qen2.checked)
				weight+=parseInt(w2.value);				
			if(qen3.checked)
				weight+=parseInt(w3.value);			
				
			if(qen4.checked)
				weight+=parseInt(w4.value);			
			if(qen5.checked)
				weight+=parseInt(w5.value);			
			if(qen6.checked)
				weight+=parseInt(w6.value);			
			if(qen7.checked)
				weight+=parseInt(w7.value);			
				
			if(weight!=100){
				alert("WRR策略权重之总合必须为100");
				return false;
			}
		}
		bandwidth = parseInt(total_bandwidth.value);
		if(bandwidth<0 || bandwidth >Number.MAX_VALUE){
			return false;
		}
		sbmtstr = sbmtstr + " bandwidth=" + total_bandwidth.value;
		lst.value = sbmtstr;
		submit();
	}	
}

function qosen_click() {
	with(document.all){		
	if(qosen.checked == false) { 
		if(!confirm("是否禁用该Qos模板")) { 
			qosen.checked = true; 
			//qosPly.style.display = qosen.checked ? "block":"";
			showhide("qosPly",qosen.checked);
			return;		
		}
	}else { 
			if(!confirm("是否启用该Qos模板")) { 
				Enable.checked = false; 
				//qosPly.style.display = qosen.checked ? "block":"";
				showhide("qosPly",qosen.checked);
				return; 
			} 
		}
	}
	on_save();
}

function qpolicy_click() {
	with(document.all){	
		if (!confirm("是否更换调度策略?")) 
		{ 
				queuepolicy[policy].checked = true;
				return; 
		}			
		queue_display();
		on_save();
	}
}

function QoSChangeTemplate()
{
	with(document.forms[0])
	{
		TemplateString.value = template.options[template.selectedIndex].value;
	}
}
function clickPage(filename)
{
			location.replace(filename);
}
</script>
</head>
<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000" onLoad="on_init();">
<blockquote>
	<DIV align="left" style="padding-left:20px; padding-top:5px;">
		<form id="form" action="/boaform/admin/formQosPolicy" method="post">
		  <table>
		  	<tr>
				<td width="150px" height="27"><b>规则模板:</b></td>
				<td>
					<select id="template" onchange="QoSChangeTemplate()" size="1" name="template">
						<option value="TR069,INTERNET" selected="true">TR069,INTERNET</option>
						<option value="TR069,VOIP,INTERNET">TR069,VOIP,INTERNET</option>
						<option value="TR069,IPTV,INTERNET">TR069,IPTV,INTERNET</option>
						<option value="TR069,VOIP,IPTV,INTERNET">TR069,VOIP,IPTV,INTERNET</option>
						<option value="OTHER">OTHER</option>
					</select>
				</td>
			</tr>
		  	<tr>
		  		<td><b>启用QoS:</b></td>
				<td><input id="qosen" value="1" name="qosen" checked="" type="checkbox" onClick=qosen_click();></td>	
			</tr>
			</table>
			<div  id="qosPly"  style="display:">
		<table>
			<tr><td width="150px"><b>上行带宽:</b></td>  
				<td><input id="total_bandwidth" maxlength="10" size="16" type="text" value="0" name="total_bandwidth">(0,8192-1000000000)bps</td>
 		    </tr> 
			<tr>
		</table>
		 <div id="qospolicyshow">
		 <table>
				<td>调度策略:</td>
      <td>
					<input type="radio"  name="queuepolicy" value="prio" onClick=qpolicy_click();>PQ
					<input type="radio"  name="queuepolicy" value="wrr" onClick=qpolicy_click();>WRR
    </td>
  </tr> 
		 </table>
		 </div>
		 <div id="mandatoryBW">
			  <table>
				<tr>
					<td width="150px">启用强制带宽</td>  
					<td>
						<input id="ip_qos_mandatory_bandwith_en" value="1" name="ip_qos_mandatory_bandwith_en" type="checkbox">                       
					</td>
				</tr> 
			  </table>
		 </div>
		 <table>
			<tr><td width="150px">启用DSCP标志</td>  
      <td>
					<input id="EnableDSCPMark" value="1" name="enable_dscp_remark" type="checkbox">                       
    </td>
  </tr> 
			<tr><td width="150px">启用802.1p标志</td>  
      <td>
				  <select id="enable_1p_remark" size="1" name="enable_1p_remark">
                        <option value="0" selected="">0标记</option>
                        <option value="1">透传</option>
                        <option value="2">重标记</option>
                  </select>	
    </td>
  </tr>
		</table>	
		  <div id="AddBtn">
                <table width="100%" border="0">
                  <tbody>
                    <tr>
                      <td><input id="AddVlan" onclick="clickPage('qos-vlanedit.asp')" value="设置VLAN值" name="AddVlan" type="button"></td>
					</tr>
                  </tbody>
				</table>
		  </div>			
 <br>
			 <div id="qostable">
		   <table class="tblList" border="1" id="lstrc">
                    <tbody>
                      <tr>
                        <td class="table_title" width="100" align="center">队列</td>
                        <td class="table_title" align="center">优先级</td>
                        <td class="table_title" align="center">使能</td>
                      </tr>
                      <tr>
                        <td align="center">Q1</td>
                        <td align="center">最高</td>
                        <td align="center"><input id="Q1Enable" value="0" checked="" type="checkbox"></td>
                      </tr>
                      <tr>
                        <td align="center">Q2</td>
                        <td align="center">高</td>
                        <td align="center"><input id="Q2Enable" value="0" checked="" type="checkbox"></td>
                      </tr>
                      <tr>
                        <td align="center">Q3</td>
                        <td align="center">中</td>
                        <td align="center"><input id="Q3Enable" value="0" checked="" type="checkbox"></td>
  </tr>
		  	<tr>
                        <td align="center">Q4</td>
                        <td align="center">低</td>
                        <td align="center"><input id="Q4Enable" value="0" type="checkbox"></td>
			</tr>
                    </tbody>
		  </table>
		  </div>
		  
		  <div id="AddBtn">
                <table width="100%" border="0">
                  <tbody>
                    <tr>
                      <td><input id="AddCls" onclick="clickPage('qos-clsedit_new.asp')" value="进入分类编辑页面" name="AddCls" type="button"></td>
			</tr>
                  </tbody>
		  </table>
		  </div>
		  </div>		  
		  </div>
		  <br><br>
		  <table width="828px">
					<tbody>
					<td colspan="2">
						<p align="center">
							<input id="btnOK" onclick="on_save();"  type="button" class="btnsaveup"  value="确定">&nbsp;&nbsp;
							<input id="btnCancel" onclick="on_save();" type="button" class="btnsaveup"  value="取消">
							
						</p>
					</td>
					</tbody>
		 </table>
		  <input type="hidden" id="lst" name="lst" value="">
		  <input type="hidden" name="TemplateString" value="">
		  <input type="hidden" name="submit-url" value="/net_qos_imq_policy.asp">
		</form>
	</DIV>
</blockquote>
</body>
<%addHttpNoCache();%>
</html>
