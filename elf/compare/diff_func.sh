#!/bin/bash

disasm_msg1='./func_disasm_old';
disasm_msg2='./func_disasm_new';
disasm_diffmsg="./disasm_diffmsg";
file1=$1;
file2=$2;
diffflag=0;

function main()
{
	if [ -e "${disasm_msg1}" ];then
		echo > $disasm_msg1;
	else
		touch $disasm_msg1;
	fi
	if [ -e "${disasm_msg1}" ];then
		echo > $disasm_msg2;
	else
		touch $disasm_msg2;
	fi
	disassemble;
	diff_start;
}

function disassemble()
{
	if [ ! -e "$file1" ];then
		echo "can not find file";exit 1;
	fi
	if [ ! -e "$file2" ];then
		echo "can not find file";exit 1;
	fi
	`objdump -d $file1 > $disasm_msg1  2>&1`;
	`objdump -d $file2 > $disasm_msg2  2>&1`;
}

function diff_start()
{
	count1=`cat $disasm_msg1 | wc -l`;
	count2=`cat $disasm_msg2 | wc -l`;
	line_limit=0;
	if [ $count1 -ne $count2 ];then
		echo "line num is differ";
		exit 1;
	fi
	if [ -e "$disasm_diffmsg" ];then
		echo > $disasm_diffmsg;
	else
		touch $disasm_diffmsg;
	fi
	diff $disasm_msg1 $disasm_msg2 > $disasm_diffmsg 2>&1;
	count=`cat $disasm_diffmsg|wc -l`;
	index=1;
	funcname="";
	while [ $index -le $count ]
	do
		line=`cat $disasm_diffmsg |sed -n ${index}p| sed -n '/^[0-9]/p' | grep c`;
		if [ "$line" != "" ];then
			linenum=${line##*c};
		fi
		while [ 1 ]
		do
			if [ $linenum -le 1 ];then
				break;
			fi
			funcname=`cat $disasm_msg1|sed -n ${linenum}p|grep '>:'`;
			if [ "$funcname" != "" ];then
				echo $funcname;
				((line_limit=$line_limit+1))
				if [ $line_limit -gt 6 ];then
					exit;
				fi
				break;
			fi
			((linenum=$linenum-1))
		done
		((index=$index+1))
	done
}

main;
