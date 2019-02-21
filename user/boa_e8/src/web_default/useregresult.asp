<!DOCTYPE HTML>
<meta http-equiv="X-UA-Compatible" content="IE=EmulateIE7" />
<!-- add by ql_xu 2008-05-23 -->
<html>
<head>
<title>中国电信</title>
<meta http-equiv=pragma content=no-cache>
<meta http-equiv=cache-control content="no-cache, must-revalidate">
<meta http-equiv=content-type content="text/html; charset=gbk">
<meta http-equiv=content-script-type content=text/javascript>
<meta http-equiv="X-UA-Compatible" content="IE=Edge" />
<style>
body { 
	font-family: "华文宋体";
	background-attachment: fixed;
	<% regresultBodyStyle(); %>
	background-position: center top;
	text-align:center;
}

div.msg {
	font-size: 20px;
	position: relative;
	top: 100px;
	margin: auto;
	width: 400px;
	text-align: center;
}

div.backlogin {
	font-size: 7px;
	position: relative;
	<% regresultLoginStyle(); %>
	top: 40px;
	margin: auto;
	width: 200px;
	text-align: right;
	color:black;
	text-decoration:underline;
}
td {
	border:none;
}
table {
	border-collapse:collapse;
	border-spacing:0;
}
body,form{		
	text-align: center;
}
form{
	margin: 0 auto;
}
.progress{
	width:395px;
	position: relative;
}

a:link{
    color: #000000;
    text-decoration: none;
}
#main_div{
	margin: 0 auto;
	text-align:center;
	<% regresultMainDivStyle(); %>
}
</style>
 
<script type='text/javascript'> 
	/* please define the parameters as you need*/
	 var init = 0;
	 var cellwidth= 4;
	 var cellheight= 25; 
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
	document.form1.percent.style.display ='none';
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
<body  onload="on_init()" >
<div id="main_div">
	<div id="blank_div" <% regresultBlankDivStyle(); %>></div>
	<div id="login_" class=backlogin>
		<a id="login_font" href="/admin/login.asp" <% regresultLoginFontStyle(); %>>返回登录页面</a>
	</div>
	<div id="regResult" class=msg>
		<% UserAccountRegResult(); %>
	</div>	
</div>
</body>
<%addHttpNoCache();%>
</html>
