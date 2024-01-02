rule SocGholish_JS {
    meta:
        author = "Dusty Miller"
		description = "ZPHP Javascript detection. This will require updates with changes"
		date = "01/02/2024"
		version = "1.0"
		hash = "ba92dcef48b9e6881de557ff5e5aa23415365810809b426925e6ec3de597e0aa"
    strings:
        $1 = "//@cc_on@*//*@if(1){"
        $2 = "while(!![])"
        $3 = "['push']"
        $4 = "catch"
        $5 = "['shift']"
        $6 = "['charCodeAt']"
        $7 = "['toString']"
        $8 = "return decodeURIComponent"
        $9 = "='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=';"
        $10 = ";}@end@*/"
    condition:
        all of them and filesize < 10KB and $1 at 0 and $10 at (filesize-9)
}
