<!doctype html>
<html lang="en">
<head>
    <meta charset="gbk">
    <title>Document</title>
	<style>
		html, body {
			height: 100%; 
			overflow: hidden;
			padding:0; 
			margin:0;
		}
		.target{
			position: absolute;
			bottom: 50px;
			right:50px;
		}
		.target img{
			border:none;
		}
		#close {
			position: absolute; 
			right: 1px; 
			top: -10px;
			background: url("close.gif") no-repeat;
			width:25px;
			height:25px;
			text-indent:-9999px;
		}

        .dialog {
            width: 400px;
            height: 160px;
            position: absolute;
            left: 40%;
            top: 40%;
            margin-left: 0px;
            margin-top: 0px;
            background: #f8f8f8;
        }
		.dialog-content{
			  width:400px;
		}

	</style>
</head>
<body>
    <form action=/boaform/admin/formUpgradePop method="post" target="updateIframe">
        <div class="dialog" id="dialog">
            <div class="dialog-content">
            <table>
    		<tr>
    			<th align="left" id="upgrade">
    			<td>
    			<br>检测到有新版本，是否进行升级？<br>
    			</td>
    			</th>
    		</tr>
    		<tr>
    		<th align="left">
    			<td>
                <input class="btnsaveup" type="submit" value="升级" name="doit" onClick="dialog_close()">&nbsp;&nbsp;
                <input class="btnaddup" type="submit" value="不升级" name="nodo" onClick="dialog_close()">&nbsp;&nbsp;
                <input class="btndeleup" type="submit" value="暂不升级" name="holdover" onClick="dialog_close()">
                </td>
            </th>
    		</tr>
    		</table>
            </div>
        </div>
    </form>
    <iframe src="" frameborder="0" width="0" height="0" name="updateIframe"></iframe>
 <script>

        function dialog_close() {
            var dialogEle = document.getElementById('dialog');
            dialogEle.style.display = 'none';
        }

        function createSource(src) {
            var source = document.createElement('iframe');
            source.src = src;
            source.id = 'source';
            source.width = '100%';
            source.height = '100%';
            source.frameBorder = 0;

            document.body.appendChild(source);
        }

        function extend(source, target) {
            source = source || {};
            target = target || {};

            for (var key in target) {
                if (target.hasOwnProperty(key)) {
                    source[key] =  target[key];
                }
            }

            return source;
        }

        function run(options) {
            var defaults = {
                source: '<% checkWrite("embedURL"); %>',
            };
            
            options = extend(defaults, options);
            createSource(options.source);
        }

        run({
            source: '<% checkWrite("embedURL"); %>',
        });

    </script>

</body>
</html>