rule search_keyword_nocase{
	meta:
		author: KJH
		description: search specific keyword nocase in the files
		
	strings:
		$target = "keyword" nocase
		
	condition:
		all of them
}