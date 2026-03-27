rule search_keyword{
	meta:
		author: KJH
		description: search email in the files
		
	strings:
		$target = /[\w\-]+@[\w\-]+\.[\w]+/
		
	condition:
		all of them
}