<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<HTML>
<HEAD>
<TITLE>Unicom</TITLE>
<META http-equiv=pragma content=no-cache>
<META http-equiv=cache-control content="no-cache, must-revalidate">
<META http-equiv=content-type content="text/html; charset=gbk">
<META http-equiv=content-script-type content=text/javascript>
<style type=text/css>
@import url(/style/default.css);
</style>
<style>
body { 
	font-family: "微软雅黑";
	background-attachment: fixed;
	/*background-image: url('image/loid_register.gif');*/
	background-repeat: no-repeat;
	background-position: center top;
	text-align:center;
	background:#EFF1EE;
}

div.msg {
	font-size: 20px;
}


body,form{		
	text-align: center;
	padding: 0;
	margin: 0;
}
form{
	margin: 0 auto;
}
.progress{

}
#main_div{
	text-align: center;
	width: 600px;
	min-height: 300px;
	position: absolute;
	top: 320px;
	left: 360px;
}

#table1{
	border:0 none;
	background: url(../image/progress_bar.png) repeat-x;
	border: 1px solid #202020;
}
.reg_olt{
	font-size: 20px;
	margin: 0;
	padding-bottom: 20px;
}
.error_ifo{
	background: url(../image/error_icon.png) no-repeat;
	height: 102px;
	padding-left: 130px;
	padding-top: 34px;
}
.back_ifo{
	position: absolute;
	top: 130px;
	left: 315px;
}
.reg_no{
	font-size: 20px;
	position: absolute;
	top: -70px;
	left: 130px;
	color: #c0c0c0;
}
</style>
 
<script type='text/javascript'> 
	/* please define the parameters as you need*/
	 var init = 0;
	 var cellwidth= 4;
	 var cellheight= 26; 
	 var progresscolor = '#ef8218';  
	 
	 
	 var totalcell=100;
	 var tablewidth=totalcell*cellwidth;	 
	 
   function createTable() {
       var t = document.createElement('table');
	   t.setAttribute('border', '0');
	   t.setAttribute('bordercolor', progresscolor);
	   t.setAttribute('id', 'tbl');
	   t.setAttribute('cellspacing', '0');
	   t.setAttribute('cellpadding', '0');
	   t.style.height = cellheight+"px";
	   t.style.width = tablewidth+"px";
	   
	   
       for (var i = 0; i < 1; i++) {
        var r = t.insertRow(0);

        for (var j = 0; j < totalcell; j++) {
			var c = r.insertCell(0);
			c.style.height = cellheight+"px";
			c.style.width = cellwidth+"px";
        }
       }
      
       var divtable =  document.getElementById('table1');
	   divtable.appendChild(t);
	   divtable.style.height = cellheight+"px";
	   divtable.style.width = tablewidth+"px";
	   document.form1.style.width=tablewidth+"px";
   }
   var bar = 0;
	function count(){
	bar= bar+1
	var table=document.getElementById("tbl");	
	for(i=0; i< bar; i++){
	  var c = table.rows[0].cells[i];
	  c.style.backgroundColor = progresscolor;
	}
	document.form1.percent.value=bar+"%";
	if (bar<totalcell)
	{setTimeout("count()",200);}
	else
	{window.location = "#";}
}

function setProgressVal(val){
	
	pecent_val = val;
	var table=document.getElementById("tbl");	
	for(i=0; i< pecent_val; i++){
	  var c = table.rows[0].cells[i];
	  c.style.backgroundColor = progresscolor;
	}
	document.form1.percent.value=pecent_val+"%";
}

function setProgressDone(){
	setProgressVal(0);
	document.getElementById('progress_id').style.display = 'none';
}

function hideProgress(){
	document.getElementById('progress_id').style.display = 'none';
}

function on_init()
{
	var ok = document.getElementById("ok");

	if (ok) {
		if (window.top != window.self) {
			// in a frame
			ok.style.display = "none";
		} else {
			// the topmost frame
			ok.style.display = "";
		}
	}

	var id_return = document.getElementById("return");
	if(!id_return && !ok)
		setTimeout(function(){
		   window.location.reload(true);
		}, 5000);
}

</script>
</head>

<!--主页代码-->
<body onload="on_init()" >
	<div class="Unicom_bg">
		<p class="site">网上营业厅 www.10010.com  &nbsp;&nbsp; 客服热线10010  &nbsp;&nbsp; 充值专线10011</p>
		<!-- <div class="backlogin"><a id="login_font" href="admin/login.asp">返回登录页面</a></div>  -->	
		<div id="main_div">	 
			<table cellspacing="0" width="530" height="70" align="center">
				<tr>
					<td>
						<div id="blank_div" ></div>
						<div class="top_bar">
							<div id="regResult" class=msg>
								<% UserAccountRegResult(); %>
							</div>	
						</div>
						
					</td>
				</tr>
			</table>
		</div>
	</div>
</body>
<%addHttpNoCache();%>
</html>
