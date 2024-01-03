rule RR_Url
{
    meta:
        author = "Dusty Miller"
        description = "RogueRaticate URL Yara Rule"
        date = "01/03/2024"
        version = "1.0"
    strings:
        $shortcut = "[InternetShortcut]"
        $url = "URL=file://"
        $urlre = /URL=file\:\/\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}@80\/\S+(\.zip)?\S+\.hta/
    condition:
        all of them
}
rule RR_hta
{
    meta:
        author = "Dusty Miller"
        description = "RogueRaticate HTA Yara Rule"
        date = "01/03/2024"
        version = "1.0"
    strings:
        $table = "<table STYLe=\"wIdTh:100%\">"
        $script = "<script language=\"vBsCrIPt\">"
        $eval = "Execute Eval("
        $close = "Close"
    condition:
        all of them
}
