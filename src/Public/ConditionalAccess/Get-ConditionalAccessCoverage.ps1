function Get-ConditionalAccessCoverage {
    <#
    .SYNOPSIS
        Analyzes Conditional Access policy coverage across users, apps, and scenarios.
    
    .DESCRIPTION
        Examines all Conditional Access policies and determines coverage levels:
        - User coverage: Which users/groups are protected vs unprotected
        - Application coverage: Which apps have CA policies vs are open
        - Platform coverage: Windows, iOS, Android, macOS, Linux
        - Location coverage: Named locations and trusted networks
        - Scenario matrix: MFA, device compliance, sign-in risk combinations
    
    .PARAMETER MockData
        Hashtable containing mock Graph API responses for testing without a tenant.
        Keys: Policies, Users, Groups, Applications, NamedLocations
    
    .PARAMETER IncludeDisabled
        Include disabled policies in coverage analysis.
    
    .PARAMETER Detailed
        Include per-policy breakdown in output.
    
    .EXAMPLE
        Get-ConditionalAccessCoverage
        
    .EXAMPLE
        Get-ConditionalAccessCoverage -Detailed -Verbose
    
    .EXAMPLE
        # With mock data for testing
        $mock = @{
            Policies = @(...)
            Users = @(...)
        }
        Get-ConditionalAccessCoverage -MockData $mock
    
    .OUTPUTS
        PSCustomObject with coverage analysis results
    #>
    [CmdletBinding()]
    param(
        [hashtable]$MockData,
        [switch]$IncludeDisabled,
        [switch]$Detailed
    )
    
    $UseMock = $null -ne $MockData
    
    Write-Verbose "Starting Conditional Access coverage analysis (Mock: $UseMock)..."
    
    #region Data Retrieval
    if ($UseMock) {
        Write-Verbose "Using mock data for analysis"
        $Policies = $MockData.Policies ?? @()
        $Users = $MockData.Users ?? @()
        $Groups = $MockData.Groups ?? @()
        $ServicePrincipals = $MockData.ServicePrincipals ?? @()
        $NamedLocations = $MockData.NamedLocations ?? @()
    }
    else {
        try {
            Write-Verbose "Retrieving Conditional Access policies..."
            $Policies = Get-MgIdentityConditionalAccessPolicy -All
            
            Write-Verbose "Retrieving users..."
            $Users = Get-MgUser -All -Property Id, DisplayName, UserPrincipalName, AccountEnabled, UserType
            
            Write-Verbose "Retrieving groups..."
            $Groups = Get-MgGroup -All -Property Id, DisplayName, GroupTypes, SecurityEnabled
            
            Write-Verbose "Retrieving service principals..."
            $ServicePrincipals = Get-MgServicePrincipal -All -Property Id, DisplayName, AppId, ServicePrincipalType
            
            Write-Verbose "Retrieving named locations..."
            $NamedLocations = Get-MgIdentityConditionalAccessNamedLocation -All
        }
        catch {
            throw "Failed to retrieve data from Microsoft Graph: $_"
        }
    }
    
    Write-Verbose "Retrieved: $($Policies.Count) policies, $($Users.Count) users, $($Groups.Count) groups"
    #endregion
    
    #region Filter Policies
    $ActivePolicies = $Policies | Where-Object {
        if ($IncludeDisabled) { return $true }
        $_.State -in @('enabled', 'enabledForReportingButNotEnforced')
    }
    
    $EnforcedPolicies = $ActivePolicies | Where-Object { $_.State -eq 'enabled' }
    $ReportOnlyPolicies = $ActivePolicies | Where-Object { $_.State -eq 'enabledForReportingButNotEnforced' }
    
    Write-Verbose "Active policies: $($ActivePolicies.Count) (Enforced: $($EnforcedPolicies.Count), Report-only: $($ReportOnlyPolicies.Count))"
    #endregion
    
    #region User Coverage Analysis
    Write-Verbose "Analyzing user coverage..."
    
    $UserCoverage = @{
        AllUsersTargeted = $false
        ExplicitlyIncluded = [System.Collections.ArrayList]::new()
        ExplicitlyExcluded = [System.Collections.ArrayList]::new()
        GroupsIncluded = [System.Collections.ArrayList]::new()
        GroupsExcluded = [System.Collections.ArrayList]::new()
        RolesIncluded = [System.Collections.ArrayList]::new()
        GuestsCovered = $false
        MembersCovered = $false
    }
    
    foreach ($Policy in $ActivePolicies) {
        $Conditions = $Policy.Conditions.Users
        
        # Check if "All" users targeted
        if ($Conditions.IncludeUsers -contains 'All') {
            $UserCoverage.AllUsersTargeted = $true
        }
        
        # Check guest/member coverage
        if ($Conditions.IncludeUsers -contains 'GuestsOrExternalUsers' -or $Conditions.IncludeGuestsOrExternalUsers) {
            $UserCoverage.GuestsCovered = $true
        }
        
        # Track included groups
        foreach ($GroupId in $Conditions.IncludeGroups) {
            if ($GroupId -and $GroupId -notin $UserCoverage.GroupsIncluded) {
                [void]$UserCoverage.GroupsIncluded.Add($GroupId)
            }
        }
        
        # Track excluded groups
        foreach ($GroupId in $Conditions.ExcludeGroups) {
            if ($GroupId -and $GroupId -notin $UserCoverage.GroupsExcluded) {
                [void]$UserCoverage.GroupsExcluded.Add($GroupId)
            }
        }
        
        # Track included roles
        foreach ($RoleId in $Conditions.IncludeRoles) {
            if ($RoleId -and $RoleId -notin $UserCoverage.RolesIncluded) {
                [void]$UserCoverage.RolesIncluded.Add($RoleId)
            }
        }
        
        # Track excluded users
        foreach ($UserId in $Conditions.ExcludeUsers) {
            if ($UserId -and $UserId -notin $UserCoverage.ExplicitlyExcluded) {
                [void]$UserCoverage.ExplicitlyExcluded.Add($UserId)
            }
        }
    }
    
    # Calculate user coverage percentage
    $TotalUsers = $Users.Count
    $CoveredUsers = 0
    
    if ($UserCoverage.AllUsersTargeted) {
        $CoveredUsers = $TotalUsers - $UserCoverage.ExplicitlyExcluded.Count
    }
    else {
        # Count users in covered groups
        $CoveredUserIds = [System.Collections.Generic.HashSet[string]]::new()
        
        foreach ($GroupId in $UserCoverage.GroupsIncluded) {
            if (-not $UseMock) {
                try {
                    $Members = Get-MgGroupMember -GroupId $GroupId -All
                    foreach ($Member in $Members) {
                        [void]$CoveredUserIds.Add($Member.Id)
                    }
                }
                catch {
                    Write-Verbose "Could not enumerate group $GroupId: $_"
                }
            }
        }
        
        # Add explicitly included users
        foreach ($UserId in $UserCoverage.ExplicitlyIncluded) {
            [void]$CoveredUserIds.Add($UserId)
        }
        
        # Remove excluded users
        foreach ($UserId in $UserCoverage.ExplicitlyExcluded) {
            [void]$CoveredUserIds.Remove($UserId)
        }
        
        $CoveredUsers = $CoveredUserIds.Count
    }
    
    $UserCoveragePercent = if ($TotalUsers -gt 0) { [math]::Round(($CoveredUsers / $TotalUsers) * 100, 1) } else { 0 }
    #endregion
    
    #region Application Coverage Analysis
    Write-Verbose "Analyzing application coverage..."
    
    $AppCoverage = @{
        AllAppsTargeted = $false
        OfficeAppsTargeted = $false
        ExplicitlyIncluded = [System.Collections.ArrayList]::new()
        ExplicitlyExcluded = [System.Collections.ArrayList]::new()
    }
    
    # Well-known Microsoft app IDs
    $MicrosoftApps = @{
        'Office365' = '00000002-0000-0ff1-ce00-000000000000'
        'AzurePortal' = 'c44b4083-3bb0-49c1-b47d-974e53cbdf3c'
        'AzureManagement' = '797f4846-ba00-4fd7-ba43-dac1f8f63013'
        'Graph' = '00000003-0000-0000-c000-000000000000'
        'Exchange' = '00000002-0000-0ff1-ce00-000000000000'
        'SharePoint' = '00000003-0000-0ff1-ce00-000000000000'
        'Teams' = 'cc15fd57-2c6c-4117-a88c-83b1d56b4bbe'
    }
    
    foreach ($Policy in $ActivePolicies) {
        $AppConditions = $Policy.Conditions.Applications
        
        if ($AppConditions.IncludeApplications -contains 'All') {
            $AppCoverage.AllAppsTargeted = $true
        }
        
        if ($AppConditions.IncludeApplications -contains 'Office365') {
            $AppCoverage.OfficeAppsTargeted = $true
        }
        
        foreach ($AppId in $AppConditions.IncludeApplications) {
            if ($AppId -and $AppId -notin @('All', 'Office365', 'None') -and $AppId -notin $AppCoverage.ExplicitlyIncluded) {
                [void]$AppCoverage.ExplicitlyIncluded.Add($AppId)
            }
        }
        
        foreach ($AppId in $AppConditions.ExcludeApplications) {
            if ($AppId -and $AppId -notin $AppCoverage.ExplicitlyExcluded) {
                [void]$AppCoverage.ExplicitlyExcluded.Add($AppId)
            }
        }
    }
    
    $TotalApps = $ServicePrincipals.Count
    $AppCoveragePercent = if ($AppCoverage.AllAppsTargeted) { 
        100 - [math]::Round(($AppCoverage.ExplicitlyExcluded.Count / [math]::Max($TotalApps, 1)) * 100, 1)
    }
    else {
        [math]::Round(($AppCoverage.ExplicitlyIncluded.Count / [math]::Max($TotalApps, 1)) * 100, 1)
    }
    #endregion
    
    #region Platform Coverage Analysis
    Write-Verbose "Analyzing platform coverage..."
    
    $Platforms = @('windows', 'iOS', 'android', 'macOS', 'linux', 'windowsPhone')
    $PlatformCoverage = @{}
    
    foreach ($Platform in $Platforms) {
        $PlatformCoverage[$Platform] = @{
            Included = $false
            Excluded = $false
            PolicyCount = 0
        }
    }
    
    foreach ($Policy in $ActivePolicies) {
        $PlatformConditions = $Policy.Conditions.Platforms
        
        if ($null -eq $PlatformConditions -or $PlatformConditions.IncludePlatforms -contains 'all') {
            # Policy applies to all platforms
            foreach ($Platform in $Platforms) {
                $PlatformCoverage[$Platform].Included = $true
                $PlatformCoverage[$Platform].PolicyCount++
            }
        }
        else {
            foreach ($Platform in $PlatformConditions.IncludePlatforms) {
                if ($Platform -and $PlatformCoverage.ContainsKey($Platform)) {
                    $PlatformCoverage[$Platform].Included = $true
                    $PlatformCoverage[$Platform].PolicyCount++
                }
            }
        }
        
        foreach ($Platform in $PlatformConditions.ExcludePlatforms) {
            if ($Platform -and $PlatformCoverage.ContainsKey($Platform)) {
                $PlatformCoverage[$Platform].Excluded = $true
            }
        }
    }
    
    $CoveredPlatforms = ($PlatformCoverage.GetEnumerator() | Where-Object { $_.Value.Included -and -not $_.Value.Excluded }).Count
    $PlatformCoveragePercent = [math]::Round(($CoveredPlatforms / $Platforms.Count) * 100, 1)
    #endregion
    
    #region Control Coverage Analysis
    Write-Verbose "Analyzing grant control coverage..."
    
    $ControlCoverage = @{
        MFA = @{ Enforced = 0; ReportOnly = 0 }
        CompliantDevice = @{ Enforced = 0; ReportOnly = 0 }
        HybridJoined = @{ Enforced = 0; ReportOnly = 0 }
        ApprovedApp = @{ Enforced = 0; ReportOnly = 0 }
        AppProtection = @{ Enforced = 0; ReportOnly = 0 }
        PasswordChange = @{ Enforced = 0; ReportOnly = 0 }
        Block = @{ Enforced = 0; ReportOnly = 0 }
        AuthStrength = @{ Enforced = 0; ReportOnly = 0 }
    }
    
    foreach ($Policy in $ActivePolicies) {
        $IsEnforced = $Policy.State -eq 'enabled'
        $Category = if ($IsEnforced) { 'Enforced' } else { 'ReportOnly' }
        $Controls = $Policy.GrantControls.BuiltInControls
        
        if ($Controls -contains 'mfa') { $ControlCoverage.MFA[$Category]++ }
        if ($Controls -contains 'compliantDevice') { $ControlCoverage.CompliantDevice[$Category]++ }
        if ($Controls -contains 'domainJoinedDevice') { $ControlCoverage.HybridJoined[$Category]++ }
        if ($Controls -contains 'approvedApplication') { $ControlCoverage.ApprovedApp[$Category]++ }
        if ($Controls -contains 'compliantApplication') { $ControlCoverage.AppProtection[$Category]++ }
        if ($Controls -contains 'passwordChange') { $ControlCoverage.PasswordChange[$Category]++ }
        if ($Controls -contains 'block') { $ControlCoverage.Block[$Category]++ }
        if ($Policy.GrantControls.AuthenticationStrength) { $ControlCoverage.AuthStrength[$Category]++ }
    }
    #endregion
    
    #region Location Coverage Analysis
    Write-Verbose "Analyzing location coverage..."
    
    $LocationCoverage = @{
        NamedLocationsCount = $NamedLocations.Count
        TrustedLocations = ($NamedLocations | Where-Object { $_.IsTrusted }).Count
        CountryLocations = ($NamedLocations | Where-Object { $_.ODataType -eq '#microsoft.graph.countryNamedLocation' }).Count
        IPLocations = ($NamedLocations | Where-Object { $_.ODataType -eq '#microsoft.graph.ipNamedLocation' }).Count
        PoliciesUsingLocations = 0
    }
    
    foreach ($Policy in $ActivePolicies) {
        $LocationConditions = $Policy.Conditions.Locations
        if ($LocationConditions.IncludeLocations.Count -gt 0 -or $LocationConditions.ExcludeLocations.Count -gt 0) {
            $LocationCoverage.PoliciesUsingLocations++
        }
    }
    #endregion
    
    #region Calculate Overall Score
    $OverallScore = [math]::Round((
        ($UserCoveragePercent * 0.35) +      # User coverage weighted 35%
        ($AppCoveragePercent * 0.25) +        # App coverage weighted 25%
        ($PlatformCoveragePercent * 0.20) +   # Platform coverage weighted 20%
        ([math]::Min(($ControlCoverage.MFA.Enforced / [math]::Max($EnforcedPolicies.Count, 1)) * 100, 100) * 0.20)  # MFA coverage weighted 20%
    ), 1)
    #endregion
    
    #region Build Result
    $Result = [PSCustomObject]@{
        TenantId = if ($UseMock) { 'mock-tenant' } else { (Get-MgContext).TenantId }
        AssessmentDate = Get-Date
        MockMode = $UseMock
        
        # Summary
        OverallCoverageScore = $OverallScore
        
        # Policy Counts
        PolicySummary = [PSCustomObject]@{
            Total = $Policies.Count
            Enabled = $EnforcedPolicies.Count
            ReportOnly = $ReportOnlyPolicies.Count
            Disabled = ($Policies | Where-Object State -eq 'disabled').Count
        }
        
        # User Coverage
        UserCoverage = [PSCustomObject]@{
            TotalUsers = $TotalUsers
            CoveredUsers = $CoveredUsers
            CoveragePercent = $UserCoveragePercent
            AllUsersTargeted = $UserCoverage.AllUsersTargeted
            GroupsIncludedCount = $UserCoverage.GroupsIncluded.Count
            GroupsExcludedCount = $UserCoverage.GroupsExcluded.Count
            RolesTargetedCount = $UserCoverage.RolesIncluded.Count
            ExcludedUsersCount = $UserCoverage.ExplicitlyExcluded.Count
            GuestsCovered = $UserCoverage.GuestsCovered
        }
        
        # Application Coverage
        AppCoverage = [PSCustomObject]@{
            TotalApps = $TotalApps
            CoveragePercent = $AppCoveragePercent
            AllAppsTargeted = $AppCoverage.AllAppsTargeted
            OfficeAppsTargeted = $AppCoverage.OfficeAppsTargeted
            ExplicitAppsCount = $AppCoverage.ExplicitlyIncluded.Count
            ExcludedAppsCount = $AppCoverage.ExplicitlyExcluded.Count
        }
        
        # Platform Coverage
        PlatformCoverage = [PSCustomObject]@{
            CoveragePercent = $PlatformCoveragePercent
            Platforms = $PlatformCoverage
        }
        
        # Control Coverage
        ControlCoverage = $ControlCoverage
        
        # Location Coverage
        LocationCoverage = $LocationCoverage
    }
    
    if ($Detailed) {
        $Result | Add-Member -NotePropertyName 'Policies' -NotePropertyValue ($ActivePolicies | Select-Object Id, DisplayName, State, @{N='Users';E={$_.Conditions.Users}}, @{N='Apps';E={$_.Conditions.Applications}}, @{N='Controls';E={$_.GrantControls}})
        $Result | Add-Member -NotePropertyName 'ExcludedUserIds' -NotePropertyValue $UserCoverage.ExplicitlyExcluded
        $Result | Add-Member -NotePropertyName 'ExcludedAppIds' -NotePropertyValue $AppCoverage.ExplicitlyExcluded
    }
    #endregion
    
    #region Console Output
    Write-Host ""
    Write-Host "┌─────────────────────────────────────────────────────────────┐" -ForegroundColor Cyan
    Write-Host "│  CONDITIONAL ACCESS COVERAGE ANALYSIS                       │" -ForegroundColor Cyan
    Write-Host "└─────────────────────────────────────────────────────────────┘" -ForegroundColor Cyan
    
    if ($UseMock) {
        Write-Host "  [MOCK MODE - No tenant connection]" -ForegroundColor Yellow
    }
    
    Write-Host ""
    Write-Host "  Overall Coverage Score: " -NoNewline
    $ScoreColor = switch ($OverallScore) {
        { $_ -ge 80 } { 'Green' }
        { $_ -ge 60 } { 'Yellow' }
        default { 'Red' }
    }
    Write-Host "$OverallScore%" -ForegroundColor $ScoreColor
    Write-Host ""
    
    Write-Host "  Policies: $($Policies.Count) total" -ForegroundColor White
    Write-Host "  ├─ Enabled: $($EnforcedPolicies.Count)" -ForegroundColor Green
    Write-Host "  ├─ Report-Only: $($ReportOnlyPolicies.Count)" -ForegroundColor Yellow
    Write-Host "  └─ Disabled: $(($Policies | Where-Object State -eq 'disabled').Count)" -ForegroundColor Gray
    Write-Host ""
    
    Write-Host "  Coverage Breakdown:" -ForegroundColor White
    Write-Host "  ├─ Users: $UserCoveragePercent% ($CoveredUsers of $TotalUsers)" -ForegroundColor $(if ($UserCoveragePercent -ge 80) { 'Green' } elseif ($UserCoveragePercent -ge 60) { 'Yellow' } else { 'Red' })
    Write-Host "  ├─ Applications: $AppCoveragePercent%" -ForegroundColor $(if ($AppCoveragePercent -ge 80) { 'Green' } elseif ($AppCoveragePercent -ge 60) { 'Yellow' } else { 'Red' })
    Write-Host "  └─ Platforms: $PlatformCoveragePercent% ($CoveredPlatforms of $($Platforms.Count))" -ForegroundColor $(if ($PlatformCoveragePercent -ge 80) { 'Green' } elseif ($PlatformCoveragePercent -ge 60) { 'Yellow' } else { 'Red' })
    Write-Host ""
    
    Write-Host "  Grant Controls (Enforced/Report-Only):" -ForegroundColor White
    Write-Host "  ├─ MFA Required: $($ControlCoverage.MFA.Enforced)/$($ControlCoverage.MFA.ReportOnly) policies"
    Write-Host "  ├─ Device Compliance: $($ControlCoverage.CompliantDevice.Enforced)/$($ControlCoverage.CompliantDevice.ReportOnly) policies"
    Write-Host "  ├─ Block Access: $($ControlCoverage.Block.Enforced)/$($ControlCoverage.Block.ReportOnly) policies"
    Write-Host "  └─ Auth Strength: $($ControlCoverage.AuthStrength.Enforced)/$($ControlCoverage.AuthStrength.ReportOnly) policies"
    Write-Host ""
    
    if ($UserCoverage.ExplicitlyExcluded.Count -gt 0) {
        Write-Host "  ⚠ $($UserCoverage.ExplicitlyExcluded.Count) users are excluded from CA policies" -ForegroundColor Yellow
    }
    if ($AppCoverage.ExplicitlyExcluded.Count -gt 0) {
        Write-Host "  ⚠ $($AppCoverage.ExplicitlyExcluded.Count) apps are excluded from CA policies" -ForegroundColor Yellow
    }
    
    Write-Host ""
    #endregion
    
    return $Result
}

Export-ModuleMember -Function Get-ConditionalAccessCoverage
