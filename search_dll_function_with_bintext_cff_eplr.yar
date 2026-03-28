rule search_dll_function_with_bintext_cff_eplr{
	meta:
		author: KJH
		description: search dll and functions with bintext and cff explorer
		
	strings:
		$text =  "PADDINGXX"
		$importDirectory1 = "WS2_32.dll"
		$importDirectory2 = "USER32.dll"
		$importDirectory3 = "KERNEL32.dll"
		$importDirectory4 = "ADVAPI32.dll"
		$importDirectory5 = "MSVCRT.dll"
		$importFunction1 = "FindFirstFileA"
		$importFunction2 = "CopyFileA"
		
	condition:
		all of them
}