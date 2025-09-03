$name = Read-Host "Enter the name of csv to group by providername, eventid, task"
$csv = Import-Csv "$(pwd)\$name"

$results = $csv | ? {$_.providername -ne "Injector-Attack" -and $_.providername -ne "EDRi"} |
    Group-Object providername, eventid, task |
    ? {$_.providername -ne "Injector-Attack"} | ForEach-Object {
    $providername, $eventid, $task = $_.Name -split ","
    $allExe    = $_.Group.exe
    $uniqueExe = $allExe | Sort-Object -Unique
        [PSCustomObject]@{
            providername = $providername.Trim()
            eventid      = ('{0:D4}' -f $eventid.Trim())
            task         = $task.Trim()
            event_count  = ('{0:D4}' -f $allExe.Count)
            exe_count    = ('{0:D4}' -f $uniqueExe.Count)
            exes         = ($uniqueExe -join " ")
        }
    } |
    Sort-Object providername, eventid, task
$results | Export-Csv "$(pwd)\$name-grouped-exes.csv" -NoTypeInformation 