<%SendWebHeadStr(); %>
<title>Mcast-VLAN <% multilang(LANG_MCAST_VLAN); %></title>
<script>
var links = new Array();
<% listWanName(); %>
var index =-1;
/********************************************************************
**          on document load
********************************************************************/
function getmsg(id)
{
	var str=new Array();
	//str[0]=new Array(101,"Empty is not allowed, set up again");
	str[1]=new Array(102, '<% multilang(LANG_INPUT_INTEGER); %>');
	//str[2]=new Array(103,"The vlan is reserved by system");
	return getMsgFormArray(str,arguments)
}

function getMsgFormArray(str,arg){
	var errid=0;
	var min =0;
	var max=0;
	var param=-1;
	var msg="";
	var num=arg.length;
	if(num==1){
		errid=arg[0];
	}else if(num==3){
		errid=arg[0];
		min =arg[1];
		max=arg[2];
	}else if(num==2){
		errid=arg[0];
		param=arg[1];
	}else return null;
	for(var i=0;i<str.length;i++){
		if(typeof(str[i])=="undefined"){
			alert("strings initialized fail, please check source code£¡i = "+i);
			return null;
		}if(errid==str[i][0]){
			if(min ==max&&min ==0){
				if(param==-1){
					msg=str[i][1];
				}else {
					msg=str[i][1]+param+str[i+1][1];
				}
			}else 
				msg=str[i][1]+min +"~"+max+str[i+1][1];
			return msg;
		}
	}
	return null;
}

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


function getImage(src,strmethod,id)
{
	return ("<image id=\""+id+"\" onclick=\""+ strmethod +"\" src=\"graphics/edit.gif\">");
}


function on_init()
{
	if(lstrc.rows){while(lstrc.rows.length > 1) lstrc.deleteRow(1);}
	for(var i = 0; i < links.length; i++)
	{
		var row = lstrc.insertRow(i + 1);

		row.nowrap = true;
		row.vAlign = "top";
		row.align = "center";

		var cell = row.insertCell(0);
		cell.innerHTML = links[i].servName;
		cell = row.insertCell(1);
		if(links[i].vlanId == 0)
			cell.innerHTML = "";
		else
			cell.innerHTML = links[i].vlanId;
		cell = row.insertCell(2);
		cell.innerHTML = getImage("image/edit.gif","Modify("+i+")","Btn_Modify"+i);		
	}
}

function jslSetValue(src,dst)
{
	var ss=document.getElementById(dst).value;
	document.getElementById(src).value=ss;
}
function setValue(id,value)
{
	document.getElementById(id).value=value;
}
function jslDisable(id)
{
	var i;
	var num=jslDisable.arguments.length;
	if(num==0)
		return;
	for(i=0;i<num;i++){
		document.getElementById(arguments[i]).disabled=true;
	}
}

function jslEnable(id)
{
	var i=0;
	var num=jslEnable.arguments.length;
	if(num==0)
		return;
	for(i=0;i<num;i++)
		document.getElementById(arguments[i]).disabled=false;
}

function Modify(i)
{
	getObj("modify").style.display="";
	document.getElementById("back").style.display="";
	jslEnable("Frm_mcast_vlan");
	ModifyGetValue(i);
	setValue("if_index", i);
	setValue("WanName", links[i].servName);
	index=i;
}

function back2add()
{
	/*mean user cancel modify, refresh web page again!*/	
	jslDisable("modify","back");
	for(var i=0;i<links.length;i++){
		jslDisable("Btn_Modify"+i);
	}
	setValue("if_index", -1);
	setValue("mVlan",-1);
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	getObj("mcast_vmap").submit();
}

function checkNull(value)
{
	if(value==""||value==null)
		return false;
	else 
		return true;
}

function checkInteger(str){
	if(str.charAt(0)=='-')
		str=str.substr(1);
	if(str.match("^[0-9]+\$"))
		return true;
	return false;
}


function checkIntegerRange(value)
{

	if(checkNull(value)==false){
		return -1;
	}
	if(checkInteger(value)!=true)
		return -2;

	return true;
}

function Check_IntegerRange(value,Frm,Fnt)
{
	var msg;
	var tem=checkIntegerRange(value);
	if(tem==-1){
		//delete mVid!!
		//msg=getmsg(101);
		//alert(msg);
		//getObj(Frm).focus();
		return true;
	}else if(tem==-2){
		msg=getmsg(102);
		alert(msg);
		getObj(Frm).focus();
		return false;
	}else if(tem==-3){
		msg=getmsg(103);
		alert(msg);
		getObj(Frm).focus();
		return false;
	}
	return true;
}

function pageCheckValue()
{
	var IgmpVlan=getValue("Frm_mcast_vlan");
	if(IgmpVlan!=""){
		if(Check_IntegerRange(IgmpVlan,"Frm_mcast_vlan","Fnt_mcast_vlan")!=true){
			return false;
		}
	}else{
		//delete mVid!!!!
		//alert(getmsg(101));
		
		//return false;		
	}
	return true;
}

function RmZero(str)
{
	while(str.indexOf("0")==0&&str.length>1){
		str=str.substr(1);
	}
	return str;
}
function ReSetValueRmZero(ID){
	var num=ReSetValueRmZero.arguments.length;
	var obj;
	if(num==0)
		return;
	for(i=0;i<num;i++){
		obj=document.getElementById(arguments[i]);
		if(obj!=null &&obj.value!=null &&obj.value!=""){
			if(obj.value.length>10){
				return false;
			}
			obj.value=RmZero(obj.value);
		}
	}
}

function pageSetValue()
{
	var vlan;
	if((getValue("Frm_mcast_vlan")!="")&&(getValue("Frm_mcast_vlan")!=null )){
		vlan = getValue("Frm_mcast_vlan");
		setValue("mVlan",vlan);
	}
	else{
		//delete mVid!!!!
		setValue("mVlan",0);
	}
}

function ModifyGetValue(i)
{

}

function ModifyApply()
{
	ReSetValueRmZero("Frm_mcast_vlan");
	if(pageCheckValue()==true){
		pageSetValue();

		postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
		return true;
	}else{
		pageSetValue();
		return false;
	}
	return false;
}
</SCRIPT>
</head>

<body onLoad="on_init();">
<div class="intro_main ">
	<p class="intro_title"><% multilang(LANG_MCAST_VLAN); %></p>
</div>

<form id="mcast_vmap" action=/boaform/admin/formMcastVlanMapping method=POST name=mcast_vmap>	
<div class="data_common data_common_notitle">
	<table id="mcast_table">
		<tr>
			<th id="Fnt_mcast_vlanA"><% multilang(LANG_MCAST_VLAN_SETUP); %></th>
			<td><input name="Frm_mcast_vlan" id="Frm_mcast_vlan" type="text" class="inputId"  disabled="true" value="" size="15" /></td>
		</tr>
	</table>
</div>
<div class="btn_ctl">
	<input class="link_bg" type="submit" value="<% multilang(LANG_APPLY); %>" id="modify" style="display:none" onclick="return ModifyApply();" />
	<input class="link_bg" name="back" type="button" id="back" value="<% multilang(LANG_UNDO); %>"  onclick="back2add()" style="display:none"/>
</div>

<div class="data_common data_vertical">
	<table id="lstrc" >
		<tr class="hdb" align="center" nowrap>
			<th><% multilang(LANG_INTERFACE); %></th>
			<th><% multilang(LANG_MCAST_VLAN); %></th>
			<th><% multilang(LANG_MODIFY); %></th>
		</tr>
	</table>
</div>
<input type='hidden' name=if_index ID=if_index value=''>		
<input type='hidden' name=mVlan ID=mVlan value=''>
<input type='hidden' name=WanName ID=WanName value=''>
<input type="hidden" name="submit-url" value="/app_iptv.asp">
<input type="hidden" name="postSecurityFlag" value="">
</form>
<br><br>
</body>
</html>
