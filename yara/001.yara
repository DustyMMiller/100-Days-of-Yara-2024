rule ZPHP_JS {
    meta:
        author = "Dusty Miller"
        description = "ZPHP Javascript detection. This will require updates with changes"
        date = "01/01/2024"
        version = "1.0"
        hash = "7791a5f2d1b2aabc186a9f42cd7d78657dc4e970f05ecb65ea729cf8643de90e"
    strings:
        $1 = ";var _0x"
        $2 = "while(!![])"
        $3 = "'MLHTTP.6.0'"
        $4 = "'L2.ServerX'"
        $5 = "'ponseText'"
        $6 = "/cache/news.php?"
    condition:
        all of them
}
