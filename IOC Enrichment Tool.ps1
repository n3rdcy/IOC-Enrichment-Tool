do {

    Clear-Host

    $VT_API = "YOUR_VIRUSTOTAL_API_KEY"
    $ABUSE  = "YOUR_ABUSEIPDB_API_KEY"

    Write-Host ""
    Write-Host "=========================" -ForegroundColor Cyan
    Write-Host "   IOC ENRICHMENT TOOL"
    Write-Host "=========================" -ForegroundColor Cyan
    Write-Host ""

    Write-Host "1 - IP"
    Write-Host "2 - Dominio"
    Write-Host "3 - Hash"
    Write-Host "4 - Sair"
    Write-Host ""

    $Opcao = Read-Host "Escolha"

    if ($Opcao -eq "1") {

        $IOC = Read-Host "IP"

        Write-Host ""
        Write-Host "[+] VirusTotal" -ForegroundColor Yellow

        try {

            $HeadersVT = @{
                "x-apikey" = $VT_API
            }

            $VT = Invoke-RestMethod `
                -Uri "https://www.virustotal.com/api/v3/ip_addresses/$IOC" `
                -Headers $HeadersVT

            $Stats = $VT.data.attributes.last_analysis_stats

            Write-Host ""
            Write-Host "Malicious :" $Stats.malicious
            Write-Host "Suspicious:" $Stats.suspicious

        }
        catch {

            Write-Host ""
            Write-Host "Erro ao consultar VirusTotal." -ForegroundColor Red

        }

        Write-Host ""
        Write-Host "Link:"
        Write-Host "https://www.virustotal.com/gui/ip-address/$IOC" -ForegroundColor Cyan

        Write-Host ""
        Write-Host "[+] AbuseIPDB" -ForegroundColor Yellow

        try {

            $Headers = @{
                Key    = $ABUSE
                Accept = "application/json"
            }

            $Resultado = Invoke-RestMethod `
                -Uri "https://api.abuseipdb.com/api/v2/check?ipAddress=$IOC&maxAgeInDays=90" `
                -Method Get `
                -Headers $Headers

            Write-Host ""
            Write-Host "Score   :" $Resultado.data.abuseConfidenceScore
            Write-Host "Reports :" $Resultado.data.totalReports
            Write-Host "Country :" $Resultado.data.countryCode
            Write-Host "ISP     :" $Resultado.data.isp

        }
        catch {

            Write-Host ""
            Write-Host "Erro ao consultar AbuseIPDB." -ForegroundColor Red

        }

        Write-Host ""
        Write-Host "Link:"
        Write-Host "https://www.abuseipdb.com/check/$IOC" -ForegroundColor Cyan

        Write-Host ""
        Write-Host "[+] Cisco Talos" -ForegroundColor Yellow

        try {

            $Talos = Invoke-RestMethod `
                -Uri "https://www.talosintelligence.com/cloud_intel/ip_reputation?ip=$IOC"

            $Rep = $Talos.reputation

            Write-Host ""
            Write-Host "Threat Level :" $Rep.threat_level_mnemonic
            Write-Host "Reputation   :" $Rep.reputation_x10
            Write-Host "Hostname     :" $Rep.hostname
            Write-Host "Organization :" $Rep.org_stats.org_info.org_name
            Write-Host "Location     :" "$($Rep.geo_location.locality), $($Rep.geo_location.state_or_province), $($Rep.geo_location.country)"

        }
        catch {

            Write-Host ""
            Write-Host "Erro ao consultar Cisco Talos." -ForegroundColor Red

        }

        Write-Host ""
        Write-Host "Link:"
        Write-Host "https://www.talosintelligence.com/reputation_center/lookup?search=$IOC" -ForegroundColor Cyan
    }

    elseif ($Opcao -eq "2") {

        $IOC = Read-Host "Dominio"

        Write-Host ""
        Write-Host "[+] VirusTotal" -ForegroundColor Yellow

        try {

            $HeadersVT = @{
                "x-apikey" = $VT_API
            }

            $VT = Invoke-RestMethod `
                -Uri "https://www.virustotal.com/api/v3/domains/$IOC" `
                -Headers $HeadersVT

            $Stats = $VT.data.attributes.last_analysis_stats

            Write-Host ""
            Write-Host "Malicious :" $Stats.malicious
            Write-Host "Suspicious:" $Stats.suspicious

        }
        catch {

            Write-Host ""
            Write-Host "Erro ao consultar VirusTotal." -ForegroundColor Red

        }

        Write-Host ""
        Write-Host "Link:"
        Write-Host "https://www.virustotal.com/gui/domain/$IOC" -ForegroundColor Cyan

        Write-Host ""
        Write-Host "[+] Cisco Talos" -ForegroundColor Yellow

        try {

            $Talos = Invoke-RestMethod `
                -Uri "https://www.talosintelligence.com/cloud_intel/url_reputation?url=$IOC"

            $Rep = $Talos.reputation

            Write-Host ""

            Write-Host "Threat Level :" $Rep.threat_level_mnemonic
            Write-Host "Organization :" $Rep.organization

            if ($Rep.aup_cat.Count -gt 0) {

                $Categorias = $Rep.aup_cat.name -join ", "
                Write-Host "Categories   :" $Categorias

            }

        }
        catch {

            Write-Host ""
            Write-Host "Erro ao consultar Cisco Talos." -ForegroundColor Red

        }

        Write-Host ""
        Write-Host "Link:"
        Write-Host "https://www.talosintelligence.com/reputation_center/lookup?search=$IOC" -ForegroundColor Cyan

        Write-Host ""
        Write-Host "[+] MXToolbox" -ForegroundColor Yellow

        Write-Host ""
        Write-Host "Link:"
        Write-Host "https://mxtoolbox.com/SuperTool.aspx?action=mx:$IOC" -ForegroundColor Cyan
    }

    elseif ($Opcao -eq "3") {

        $IOC = Read-Host "Hash"

        Write-Host ""
        Write-Host "[+] VirusTotal" -ForegroundColor Yellow

        try {

            $HeadersVT = @{
                "x-apikey" = $VT_API
            }

            $VT = Invoke-RestMethod `
                -Uri "https://www.virustotal.com/api/v3/files/$IOC" `
                -Headers $HeadersVT

            $Stats = $VT.data.attributes.last_analysis_stats

            Write-Host ""
            Write-Host "Malicious :" $Stats.malicious
            Write-Host "Suspicious:" $Stats.suspicious

        }
        catch {

            Write-Host ""
            Write-Host "Erro ao consultar VirusTotal." -ForegroundColor Red

        }

        Write-Host ""
        Write-Host "Link:"
        Write-Host "https://www.virustotal.com/gui/file/$IOC" -ForegroundColor Cyan

        Write-Host ""
        Write-Host "[+] Cisco Talos" -ForegroundColor Yellow

        Write-Host ""
        Write-Host "Link:"
        Write-Host "https://www.talosintelligence.com/talos_file_reputation?s=$IOC" -ForegroundColor Cyan
    }

    elseif ($Opcao -eq "4") {

        break

    }

    else {

        Write-Host ""
        Write-Host "Opcao invalida." -ForegroundColor Red

    }

    if ($Opcao -ne "4") {

        Write-Host ""
        Read-Host "Pressione Enter para voltar ao menu"

    }

} while ($true)
