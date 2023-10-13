 function Set-UpdatedGPOPermissions {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$TrusteeToAdd,

        [Parameter(Mandatory = $true)]
        [ValidateSet("User", "Group", "Computer")]
        [string]$TrusteeToAddType,

        [Parameter(Mandatory = $true)]
        [ValidateSet("GpoEditDeleteModifySecurity", "None", "GpoEdit", "GpoApply", "GpoRead")]
        [string]$permissionLevel,

        [Parameter(Mandatory = $true)]
        [string]$TrusteeToRemove,

        [Parameter(Mandatory = $true)]
        [ValidateSet("User", "Group", "Computer")]
        [string]$TrusteeToRemoveType,

        [string]$Prefix,

        [string]$subString,

        [switch]$WhatIf,

        [switch]$skipVerification
    )

    <#
    .SYNOPSIS
    This function sets GPO permissions by verifying the existence of, or adding a TrusteeToAdd and removing an existing TrusteeToRemove based on specified parameters.

    .DESCRIPTION
        WARNING: You CAN update yourself OUT of a GPO.  If you choose yourself as the TrusteeToRemove, and the TrusteeToAdd is not a security group in which you are a member of, you will no longer have permissions to edit the GPOs that this runs against.
        The function iterates through all GPOs and checks their permissions. It adds the specified trustee if it doesn't already exist and removes the trustee to be removed.
        This will not update any GPOs that do not have the TrusteeToRemove as an existing delegation.
        The script uses the credentials of the user or account it is being run from.  If you do not have permission to edit the security settings of a GPO, this will not work.
        Use -WhatIf and -Verbose in the parameters when running this function to see what will happen before it actually happens.

    .PARAMETER TrusteeToAdd
    The name of the trustee to add or verify existence of before removing the TrusteeToRemove.

    .PARAMETER TrusteeToAddType
    The type of the trustee to add (User, Group, or Computer).  

    .PARAMETER TrusteeToRemove
    The name of the trustee to remove.

    .PARAMETER TrusteeToRemoveType
    The type of the trustee to remove (User, Group, or Computer).

    .PARAMETER permissionLevel
    The permission level to grand the Trustee being added.

    .PARAMETER Prefix
    Optional GPO Name prefix filter to match the beginning of the GPO name.

    .PARAMETER subString
    Optional substring to filter and look for this pattern of text anywhere inside the GPO name.

    .PARAMETER WhatIf
    Optional "WhatIf" that lets you test the function first and see the outcome before doing the actual thing by adding -whatif at the end of the Set-GPOPermission commandlets.  Pairs well with -Verbose.

    .PARAMETER skipVerification
    Skips the GPOs to be evaluated verification prompt.  Use at your own risk!

    .NOTES
        Author: Daniel Barton
        GitHub: github.com/DanHalenSRI
        Prerequisite: https://learn.microsoft.com/en-us/powershell/module/grouppolicy/?view=windowsserver2022-ps
        Version: 1.1
        If you found this script helpful please let me know!

    .EXAMPLE
    Update-GPOPermissions -TrusteeToAdd "Security-Group-A" -TrusteeToAddType "Group" -TrusteeToRemove "JohnSmith" -TrusteeToRemoveType "User" -Prefix "Customer" -subString "Location" -permissionLevel "GpoEditDeleteModifySecurity" -WhatIf
    #>

    #Create Parameters dynamically based on values passed to the function
    $removeTrustee = @{
        PermissionLevel = 'None'
        Replace         = $true
        TargetName      = $TrusteeToRemove
        TargetType      = $TrusteeToRemoveType
        WhatIf          = $false        
    }

    $addTrustee = @{
        PermissionLevel = 'GpoEditDeleteModifySecurity'
        TargetName      = $TrusteeToAdd
        TargetType      = $TrusteeToAddType
        WhatIf          = $false        
    }

    if ($WhatIf) {
        $addTrustee.WhatIf = $true
        $removeTrustee.WhatIf = $true
        Write-Host "Running in -WhatIf Mode - No changes will be made"
    }

    # Gotta get 'em all!
    try {
        $allGPOs = Get-GPO -All
    }
    catch {
        Write-Warning "Error getting GPOs, unable to continue"
        return
    }

    # Filter prefix if provided
    if ($Prefix) {
        $allGPOs = $allGPOs | Where-Object -Property DisplayName -like "$Prefix*"
        Write-Verbose "Filtering GPO's by prefix: $Prefix"
    }

    # Filter substring if provided
    if ($subString) {
        $allGPOs = $allGPOs | Where-Object -Property DisplayName -like "*$subString*"
        Write-Verbose "Filtering GPO's by substring: $subString"
    }

    #Lists all GPO's that will be evaluated and ask for confirmation to proceed
    if (!$skipVerification) {

        if (!$subString -and !$Prefix) {
            Write-Host "WARNING:: This script will evaluate ALL GPOs and may take a long time.  Please consider using -Prefix or -subString to evaluate a subset of GPO's."
        }
        else {
            Write-Host "This script will evaluate the following GPOs based on the Prefix and/or subString parameters provided:"
            foreach ($gpo in $allGPOs) {
                Write-Host "$($gpo.DisplayName)"
            }
        }

        $confirmation = Read-Host "Do you want to proceed? (Y/N)"

        if ($confirmation -ne "Y") {
            Write-Host "Operation Canceled"
            return
        }
    }

    # Start processing GPOs
    foreach ($gpo in $allGPOs) {
        try {
            $permissions = Get-GPPermissions -Guid $($gpo.Id) -All
        }
        catch {
            Write-Error "Error: Unable to get Permission's on $($gpo.DisplayName)"
        }
        #Make sure we're only processing GPO's if they have the TrusteeToRemove as part of it's Permission Set
        if ($permissions.Trustee.Name -match $TrusteeToRemove) {
            Write-Verbose "$($gpo.DisplayName) Contains $TrusteeToRemove - Remediating"

            #Switch statement to perform the necessary tasks.  Easy to add more conditional rendering in the future if needed.
            switch ($permissions) {
                #IF TrusteeToAdd AND TrusteeToRemove are in the permission set - Just remove TrusteeToRemove
                { ($permissions.Trustee.Name -contains $TrusteeToAdd) -and ($permissions.Trustee.Name -contains $TrusteeToRemove) } {
                    try {
                        Set-GPPermission @removeTrustee -Guid $gpo.id
                        Write-Verbose "$($gpo.DisplayName) Already had $TrusteeToAdd, removed $TrusteeToRemove"
                    }
                    catch {
                        Write-Warning "Error setting permissions for $($gpo.DisplayName)"
                        break
                    }
                    break
                }
                #If TrusteeToAdd is not in the permission set, AND the TrusteeToRemove is - Add TrusteeToAdd first, then remove TrusteeToRemove
                { ($permissions.Trustee.Name -notcontains $TrusteeToAdd) -and ($permissions.Trustee.Name -contains $TrusteeToRemove) } {
                    try {
                        Set-GPPermission @addTrustee -Guid $gpo.id
                        Set-GPPermission @removeTrustee -Guid $gpo.id
                        Write-Verbose "$($gpo.DisplayName) - Added $TrusteeToAdd and Removed $TrusteeToRemove"
                    }
                    catch {
                        Write-Warning "Error setting permissions for $($gpo.DisplayName)"
                        break
                    }
                    break
                }
                default {
                    #This should only happen if there are funky perimssion issues
                    Write-Verbose "Error: Unable to read Permissions data on $($gpo.DisplayName)"
                    break
                }
            }
        }
    }
} 
 
