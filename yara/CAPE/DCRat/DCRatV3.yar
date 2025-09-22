rule DCRatV3 {
    meta:
        author = "ClaudioWayne"
        description = "DCRat V3 (GZIP+B64 String Decryption) Payload"
	cape_type = "DCRatV3 Payload"        
    strings:
        // DCRat
        $dc_v1_1 = "DCRat.Code" wide
        $dc_v2_1 = "DarkCrystal RAT" wide
        $dc_all_1 = "ICBfX18gICAgICAgICAgIF8gICAgICBfX18gICAgICAgICAgICAgXyAgICAgICAgXyAgIF9fXyAgICBfIF9fX19fIA0KIHwgICBcIF9fIF8gXyBffCB8X18gIC8gX198XyBfIF8gIF8gX198IHxfIF9fIF98IHwgfCBfIFwgIC9fXF8gICBffA0KIHwgfCkgLyBfYCB8ICdffCAvIC8gfCAoX198ICdffCB8fCAoXy08ICBfLyBfYCB8IHwgfCAgIC8gLyBfIFx8IHwgIA0KIHxfX18vXF9fLF98X3wgfF9cX1wgIFxfX198X3wgIFxfLCAvX18vXF9fXF9fLF98X3wgfF98X1wvXy8gXF9cX3wgIA0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHxfXy8gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIA==" wide
        $dc_all_2 = "DCRat-Log#" wide
        //GeoIP
        $geoip_all_1 = "geoplugin_city" wide fullword
        $geoip_all_2 = "geoplugin_countryName" wide fullword
        $geoip_all_3 = "geoplugin_countryCode" wide fullword
        $geoip_all_4 = "geoplugin_latitude" wide fullword
        $geoip_all_5 = "geoplugin_longitude" wide fullword
        $geoip_all_6 = "geoplugin_request" wide fullword
        $geoip_v1_1 = "geoplugin_timezone" wide fullword
        $geoip_v1_2 = "geoplugin_regionName" wide fullword
        $geoip_v2_1 = "geoplugin_region" wide fullword
        //Plugins
        $plugin_v2_1 = "[Plugin] Execute: " wide fullword
        $plugin_v2_2 = "Processing plugins [" wide fullword
        $plugin_all_1 = "Processing other information..." wide fullword
        $plugin_v1_1 = "Processing stealer plugins [" wide fullword
        $plugin_v1_2 = "Unknown command! Maybe a plugin is required?" wide fullword
        //GUI
        $gui_all_1 = "Clipboard [Text].txt" wide fullword
        $gui_all_2 = "Clipboard [Files].txt" wide fullword
        $gui_all_3 = "[Clipboard] Saving information..." wide fullword
        $gui_all_4 = "[SystemInfromation] Saving information..." wide fullword
        $gui_all_5 = "~Work.log" wide fullword
        $gui_all_6 = "Done! Elapsed time: " wide fullword
        $gui_all_7 = "[Screenshot] Saving screenshots from " wide fullword
        //Steal
        $steal_all_1 = "SELECT * FROM Win32_PnPEntity WHERE (PNPClass = 'Image' OR PNPClass = 'Camera')" wide fullword 
        $steal_all_2 = "SOFTWARE\\Valve\\Steam" wide fullword
        $steal_all_3 = "SteamPath" wide fullword 
        $steal_all_4 = "/config/loginusers.vdf" wide fullword 
        $steal_all_5 = "/steamapps/common" wide fullword
        $steal_all_6 = "TelegramPath" wide fullword
        $steal_all_7 = "Telegram" wide fullword
        $steal_all_8 = "Kotatogram" wide fullword
        $steal_all_9 = "Unigram" wide fullword
        $steal_all_10 = "Telefuel" wide fullword
        $steal_all_11 = "/tdata" wide fullword
        $steal_all_12 = "DiscordPath" wide fullword
        $steal_v1_1 = "\\discord\\Local Storage\\leveldb\\" wide fullword
        $steal_v2_1 = "discordcanary" wide fullword
        $steal_v2_2 = "Lightcord" wide fullword
        $steal_v2_3 = "discordptb" wide fullword
    condition:
        uint16(0) == 0x5a4d
         and (
                (
                    (2 of ($dc*)) 
                    or (
                    (3 of ($geoip*)) and (1 of ($plugin*)) and (2 of ($gui*)) and (5 of ($steal*))
                    )
                )
                and not (
                    (any of ($steal_v2*)) or (any of ($plugin_v2*)) or (any of ($geoip_v2*)) or (any of ($dc_v2*))
                    )
            )
}
