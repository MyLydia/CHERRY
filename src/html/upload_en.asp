<!DOCTYPE html>
<html>
<head>

<title>菜鸟教程(runoob.com)</title>
</head>
	
<style>
.file{  
	filter:alpha(opacity:0);
	opacity: 0;
	width:0px 
}	
</style>
	
<body>
<!--
<th>
<input class="inner_btn" type="file" value="Choose File" name="binary" size="20">	
<th>
-->
<input type='text' id='textfield' class='txt' />
<input type='button' class='btn' value='choose file'onclick="document.getElementById('fileField').click()" />
<input type="file" id="fileField"class="file" size="28" onchange="document.getElementById('textfield').value=this.value" />
	

</body>
</html>
