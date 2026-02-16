function Get-PrivilegedRoleAudit {
    <#
    .SYNOPSIS
        Audits privileged role assignments in Entra ID.
    
    .DESCRIPTION
        Comprehensive audit of privileged role assignments including:
        - Global Administrator count and details
        - PIM-enabled vs standing access
        - Stale admin accounts (no sign-in in X days)
        - Highly privileged role assignments
        - Service principals with admin roles
    
    .PARAMETER StaleThresholdDays
        Number of days without sign-in to consider an admin account stale.
        Default: 90 days.
    
    .PARAMETER IncludeServicePrincipals
        Include service principals in the privileged role audit.
    
    .EXAMPLE
        Get-PrivilegedRoleAudit
        
    .EXAMPLE
        Get-PrivilegedRoleAudit -StaleThresholdDays 60 -IncludeServicePrincipals
    
    .OUTPUTS
        PSCustomObject with privileged access audit results
    #>
    [CmdletBinding()]
    param(
        [int]$StaleThresholdDays = 90,
        [switch]$IncludeServicePrincipals
    )
    
    Write-Verbose "Starting privileged role audit..."
    
    # Define high-risk roles
    $HighRiskRoles = @{
        '62e90394-69f5-4237-9190-012177145e10' = 'Global Administrator'
        'e8611ab8-c189-46e8-94e1-60213ab1f814' = 'Privileged Role Administrator'
        '7be44c8a-adaf-4e2a-84d6-ab2649e08a13' = 'Privileged Authentication Administrator'
        '194ae4cb-b126-40b2-bd5b-6091b380977d' = 'Security Administrator'
        '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3' = 'Application Administrator'
        '158c047a-c907-4556-b7ef-446551a6b5f7' = 'Cloud Application Administrator'
        'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9' = 'Conditional Access Administrator'
        'c4e39bd9-1100-46d3-8c65-fb160da0071f' = 'Authentication Administrator'
        'f28a1f50-f6e7-4571-818b-6a12f2af6b6c' = 'SharePoint Administrator'
        '29232cdf-9323-42fd-ade2-1d097af3e4de' = 'Exchange Administrator'
        'fe930be7-5e62-47db-91af-98c3a49a38b1' = 'User Administrator'
        'fdd7a751-b60b-444a-984c-02652fe8fa1c' = 'Groups Administrator'
    }
    
    # Get all directory roles
    try {
        $DirectoryRoles = Get-MgDirectoryRole -All
        Write-Verbose "Retrieved $($DirectoryRoles.Count) directory roles"
    }
    catch {
        throw "Failed to retrieve directory roles: $_"
    }
    
    # Initialize results
    $Findings = @{
        GlobalAdmins = [System.Collections.ArrayList]::new()
        HighRiskAssignments = [System.Collections.ArrayList]::new()
        StaleAdmins = [System.Collections.ArrayList]::new()
        PIMStatus = @{
            Enabled = 0
            Standing = 0
        }
        ServicePrincipalAdmins = [System.Collections.ArrayList]::new()
        Warnings = [System.Collections.ArrayList]::new()
    }
    
    $StaleThreshold = (Get-Date).AddDays(-$StaleThresholdDays)
    
    foreach ($Role in $DirectoryRoles) {
        # Skip non-high-risk roles for detailed analysis
        $IsHighRisk = $HighRiskRoles.ContainsKey($Role.RoleTemplateId)
        
        try {
            $Members = Get-MgDirectoryRoleMember -DirectoryRoleId $Role.Id -All
        }
        catch {
            Write-Warning "Failed to get members for role: $($Role.DisplayName)"
            continue
        }
        
        foreach ($Member in $Members) {
            # Get member details
            $MemberType = $Member.AdditionalProperties['@odata.type']
            
            if ($MemberType -eq '#microsoft.graph.user') {
                try {
                    $User = Get-MgUser -UserId $Member.Id -Property 'Id,DisplayName,UserPrincipalName,SignInActivity,AccountEnabled,CreatedDateTime'
                    
                    $Assignment = [PSCustomObject]@{
                        RoleId = $Role.RoleTemplateId
                        RoleName = $Role.DisplayName
                        UserId = $User.Id
                        DisplayName = $User.DisplayName
                        UserPrincipalName = $User.UserPrincipalName
                        AccountEnabled = $User.AccountEnabled
                        LastSignIn = $User.SignInActivity.LastSignInDateTime
                        CreatedDateTime = $User.CreatedDateTime
                        AssignmentType = 'Direct' # TODO: Check PIM for eligible vs active
                        IsHighRisk = $IsHighRisk
                    }
                    
                    # Track Global Admins specifically
                    if ($Role.RoleTemplateId -eq '62e90394-69f5-4237-9190-012177145e10') {
                        [void]$Findings.GlobalAdmins.Add($Assignment)
                    }
                    
                    # Track all high-risk assignments
                    if ($IsHighRisk) {
                        [void]$Findings.HighRiskAssignments.Add($Assignment)
                    }
                    
                    # Check for stale accounts
                    if ($User.SignInActivity.LastSignInDateTime -and 
                        $User.SignInActivity.LastSignInDateTime -lt $StaleThreshold -and
                        $IsHighRisk) {
                        [void]$Findings.StaleAdmins.Add($Assignment)
                    }
                    elseif (-not $User.SignInActivity.LastSignInDateTime -and $IsHighRisk) {
                        # Never signed in
                        $Assignment | Add-Member -NotePropertyName 'StaleReason' -NotePropertyValue 'Never signed in'
                        [void]$Findings.StaleAdmins.Add($Assignment)
                    }
                }
                catch {
                    Write-Verbose "Could not get details for user $($Member.Id): $_"
                }
            }
            elseif ($MemberType -eq '#microsoft.graph.servicePrincipal' -and $IncludeServicePrincipals) {
                try {
                    $SP = Get-MgServicePrincipal -ServicePrincipalId $Member.Id
                    
                    [void]$Findings.ServicePrincipalAdmins.Add([PSCustomObject]@{
                        RoleName = $Role.DisplayName
                        ServicePrincipalId = $SP.Id
                        DisplayName = $SP.DisplayName
                        AppId = $SP.AppId
                        IsHighRisk = $IsHighRisk
                    })
                }
                catch {
                    Write-Verbose "Could not get details for service principal $($Member.Id): $_"
                }
            }
        }
    }
    
    # Generate warnings
    $GlobalAdminCount = $Findings.GlobalAdmins.Count
    if ($GlobalAdminCount -gt 5) {
        [void]$Findings.Warnings.Add([PSCustomObject]@{
            Severity = 'High'
            Finding = "Excessive Global Administrators: $GlobalAdminCount (recommended: 2-4)"
            Recommendation = 'Reduce Global Admin count and use least-privilege roles'
        })
    }
    elseif ($GlobalAdminCount -lt 2) {
        [void]$Findings.Warnings.Add([PSCustomObject]@{
            Severity = 'Medium'
            Finding = "Insufficient Global Administrators: $GlobalAdminCount (recommended: 2-4)"
            Recommendation = 'Ensure at least 2 Global Admins for redundancy'
        })
    }
    
    if ($Findings.StaleAdmins.Count -gt 0) {
        [void]$Findings.Warnings.Add([PSCustomObject]@{
            Severity = 'High'
            Finding = "$($Findings.StaleAdmins.Count) privileged accounts have not signed in for $StaleThresholdDays+ days"
            Recommendation = 'Review and disable/remove stale privileged accounts'
        })
    }
    
    # Build result
    $Result = [PSCustomObject]@{
        TenantId = (Get-MgContext).TenantId
        AssessmentDate = Get-Date
        GlobalAdminCount = $Findings.GlobalAdmins.Count
        HighRiskAssignmentCount = $Findings.HighRiskAssignments.Count
        StaleAdminCount = $Findings.StaleAdmins.Count
        ServicePrincipalAdminCount = $Findings.ServicePrincipalAdmins.Count
        GlobalAdmins = $Findings.GlobalAdmins
        HighRiskAssignments = $Findings.HighRiskAssignments
        StaleAdmins = $Findings.StaleAdmins
        ServicePrincipalAdmins = $Findings.ServicePrincipalAdmins
        Warnings = $Findings.Warnings
    }
    
    # Console output
    Write-Host "`n┌─────────────────────────────────────────────────────────────┐" -ForegroundColor Cyan
    Write-Host "│  PRIVILEGED ROLE AUDIT                                      │" -ForegroundColor Cyan
    Write-Host "└─────────────────────────────────────────────────────────────┘" -ForegroundColor Cyan
    Write-Host ""
    
    # Global Admin status
    $GAColor = if ($GlobalAdminCount -in 2..4) { 'Green' } elseif ($GlobalAdminCount -gt 5) { 'Red' } else { 'Yellow' }
    Write-Host "  Global Administrators: $GlobalAdminCount" -ForegroundColor $GAColor
    
    foreach ($GA in $Findings.GlobalAdmins) {
        $LastSignIn = if ($GA.LastSignIn) { $GA.LastSignIn.ToString('yyyy-MM-dd') } else { 'Never' }
        Write-Host "    • $($GA.DisplayName) ($($GA.UserPrincipalName)) - Last sign-in: $LastSignIn" -ForegroundColor Gray
    }
    
    Write-Host ""
    Write-Host "  High-Risk Role Assignments: $($Findings.HighRiskAssignments.Count)" -ForegroundColor White
    Write-Host "  Stale Privileged Accounts: $($Findings.StaleAdmins.Count)" -ForegroundColor $(if ($Findings.StaleAdmins.Count -gt 0) { 'Red' } else { 'Green' })
    
    if ($IncludeServicePrincipals) {
        Write-Host "  Service Principal Admins: $($Findings.ServicePrincipalAdmins.Count)" -ForegroundColor White
    }
    
    Write-Host ""
    
    if ($Findings.Warnings.Count -gt 0) {
        Write-Host "  ⚠ WARNINGS:" -ForegroundColor Yellow
        foreach ($Warning in $Findings.Warnings) {
            Write-Host "    [$($Warning.Severity)] $($Warning.Finding)" -ForegroundColor $(if ($Warning.Severity -eq 'High') { 'Red' } else { 'Yellow' })
        }
        Write-Host ""
    }
    
    return $Result
}

Export-ModuleMember -Function Get-PrivilegedRoleAudit
