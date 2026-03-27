rule search_hex{
	meta:
		author: KJH
		description: search specific hex data in the files
		
	strings:
		$target = {6B 65 79 77 6F 72 64}
		
	condition:
		all of them
}