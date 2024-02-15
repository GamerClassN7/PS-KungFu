function Get-CZNICDomainStatus {
    param(
        [string] $DomaninName
    )

    $response = Invoke-WebRequest -Uri ("https://www.nic.cz/whois/contact/{0}/" -f $DomaninName)

    $tableRegex = '<table[^>]*>.*?</table>'
    $tables = $response.Content -split $tableRegex | Where-Object { $_ -match '<td>|<th>' }

    # Print the extracted table text
    foreach ($table in $tables) {
        $table
    }
}