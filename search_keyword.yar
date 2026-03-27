rule search_keyword{
	meta:
		author: KJH
		description: search specific keyword in the files
		
	strings:
		$target = "keyword"
		
	condition:
		all of them
}