rule search_rule_1{
	meta:
		author: KJH
		description: search specific keyword rule_1 in the files
		
	strings:
		$target1 = "keyword1"
		$target2 = "keyword2"
		
	condition:
		any of them
		// all of them
}

rule search_rule_2{
	meta:
		author: KJH
		description: search specific keyword rule_2 in the files
		
	strings:
		$target1 = "yara_regex1"
		$target2 = "yara_regex2"
		$target3 = {72 65 67 65 78}
		
	condition:
		2 of them
		// any of them
		// all of them
}