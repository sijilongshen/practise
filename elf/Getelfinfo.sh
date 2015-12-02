#!/bin/sh

if [ "$1" = "" ];then
	echo "give file name";
	exit 1;
fi

> elfinfo;


elfFileName=$1
##取出中间的16进制代码##
readelf $elfFileName -R .rodata |awk '{if($1 != "Hex" ){print $2"\n"$3"\n"$4"\n"$5}}' > elfinfo;
##去除空行##
sed -i  '/^$/d' elfinfo;
##去除最后一行##
lineCount="`cat elfinfo|wc -l`"
sed -i "${lineCount}d" elfinfo;
#hexinfo="`cat elfinfo|tr -d '\n'`"
hexinfo="f0100020000000000000000000000000062626262626262626264275696c64626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262620068656c6c6f207562756e747521004255494c445f53564e203d2025732c2061203d2025730a00000061616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616100"
##从文件中找到字符串位置##
# 313730353300323031352d31312d323700622a602031383a32333a303700322e3100320000622a70330052656c656173652025732e25732e00622a802573204275696c64
# 17053.2015-11-27 18:23:07.2.1.2.3.Release %s.%s.%s Build
# 版本号关键字长度为 136     Build hex 4275696c64 长度为 10   Release hex 52656c65617365 长度为 14 
# 攻略：每找到一个Build关键字 查找他的前28个字符是不是Release不是的话 截掉这部分字符串继续查找
# 使用 awk 获取 Build 关键字所在下标 查询他的前 28个字符
##每找到一个关键字 ##
hexBuild="4275696c64"
hexRelease="52656c65617365"
hextmp=$hexinfo;
cutedLength=0
len="`/bin/awk "BEGIN{print index("$hexinfo","$hexBuild")}"`";
echo $len



