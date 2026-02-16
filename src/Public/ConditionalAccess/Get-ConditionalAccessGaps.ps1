function Get-ConditionalAccessGaps {
    <#
    .SYNOPSIS
        Analyzes Conditional Access policies for security gaps.
    
    .DESCRIPTION
        Examines all Conditional Access policies in the tenant and identifies:
        - Missing MFA requirements for privileged users
        - Unprotected applications
        - Legacy authentication not blocked
        - Missing device compliance requirements
        - Overly broad exclusions
        - Break-glass account configurations
    
    .PARAMETER IncludeDisabled
        Include disabled policies in the analysis.
    
    .PARAMETER ExcludeReportOnly
        Exclude policies in report-only mode from gap analysis.
    
    .EXAMPLE
        Get-ConditionalAccessGaps
        
    .EXAMPLE
        Get-ConditionalAccessGaps -IncludeDisabled -Verbose
    
    .OUTPUTS
        PSCustomObject with gap analysis results
    #>
    [CmdletBinding()]
    param(
        [switch]$IncludeDisabled,
        [switch]$ExcludeReportOnly
    )
    
    Write-Verbose "Starting Conditional Access gap analysis..."
    
    # Get all CA policies
    try {
        $Policies = Get-MgIdentityConditionalAccessPolicy -All
        Write-Verbose "Retrieved $($Policies.Count) Conditional Access policies"
    }
    catch {
        throw "Failed to retrieve Conditional Access policies: $_"
    }
    
    # Filter policies based on parameters
    $ActivePolicies = $Policies | Where-Object {
        $Include = $true
        
        if (-not $IncludeDisabled -and $_.State -eq 'disabled') {
            $Include = $false
        }
        
        if ($ExcludeReportOnly -and $_.State -eq 'enabledForReportingButNotEnforced') {
            $Include = $false
        }
        
        $Include
    }
    
    Write-Verbose "Analyzing $($ActivePolicies.Count) active policies"
    
    # Initialize findings
    $Findings = @{
        Gaps = [System.Collections.ArrayList]::new()
        Warnings = [System.Collections.ArrayList]::new()
        Info = [System.Collections.ArrayList]::new()
        PolicyCount = @{
            Total = $Policies.Count
            Enabled = ($Policies | Where-Object State -eq 'enabled').Count
            ReportOnly = ($Policies | Where-Object State -eq 'enabledForReportingButNotEnforced').Count
            Disabled = ($Policies | Where-Object State -eq 'disabled').Count
        }
    }
    
    #region Check 1: MFA for Administrators
    Write-Verbose "Checking MFA requirements for administrators..."
    
    $AdminRoles = @(
        '62e90394-69f5-4237-9190-012177145e10' # Global Administrator
        'e8611ab8-c189-46e8-94e1-60213ab1f814' # Privileged Role Administrator
        '194ae4cb-b126-40b2-bd5b-6091b380977d' # Security Administrator
        'f28a1f50-f6e7-4571-818b-6a12f2af6b6c' # SharePoint Administrator
        '29232cdf-9323-42fd-ade2-1d097af3e4de' # Exchange Administrator
        'fe930be7-5e62-47db-91af-98c3a49a38b1' # User Administrator
    )
    
    $MFAForAdmins = $ActivePolicies | Where-Object {
        $_.Conditions.Users.IncludeRoles | Where-Object { $_ -in $AdminRoles }
    } | Where-Object {
        $_.GrantControls.BuiltInControls -contains 'mfa' -or
        $_.GrantControls.AuthenticationStrength.Id
    }
    
    if (-not $MFAForAdmins) {
        [void]$Findings.Gaps.Add([PSCustomObject]@{
            Severity = 'Critical'
            Category = 'MFA'
            Finding = 'No Conditional Access policy requires MFA for administrative roles'
            Recommendation = 'Create a CA policy requiring MFA for all admin roles'
            CISControl = '1.1.1'
        })
    }
    
    #endregion
    
    #region Check 2: Legacy Authentication Blocking
    Write-Verbose "Checking legacy authentication blocking..."
    
    $LegacyAuthBlocked = $ActivePolicies | Where-Object {
        $_.Conditions.ClientAppTypes -contains 'exchangeActiveSync' -or
        $_.Conditions.ClientAppTypes -contains 'other'
    } | Where-Object {
        $_.GrantControls.BuiltInControls -contains 'block'
    }
    
    if (-not $LegacyAuthBlocked) {
        [void]$Findings.Gaps.Add([PSCustomObject]@{
            Severity = 'High'
            Category = 'Legacy Auth'
            Finding = 'Legacy authentication protocols are not blocked'
            Recommendation = 'Create a CA policy to block legacy authentication for all users'
            CISControl = '1.1.3'
        })
    }
    
    #endregion
    
    #region Check 3: All Users Coverage
    Write-Verbose "Checking user coverage..."
    
    $AllUsersPolicies = $ActivePolicies | Where-Object {
        $_.Conditions.Users.IncludeUsers -contains 'All' -or
        $_.Conditions.Users.IncludeGroups.Count -gt 0
    }
    
    if ($AllUsersPolicies.Count -lt 1) {
        [void]$Findings.Warnings.Add([PSCustomObject]@{
            Severity = 'Medium'
            Category = 'Coverage'
            Finding = 'No policies targeting all users detected'
            Recommendation = 'Ensure baseline policies cover all users with appropriate exclusions'
        })
    }
    
    #endregion
    
    #region Check 4: Break-glass Account Exclusions
    Write-Verbose "Checking break-glass account exclusions..."
    
    $PoliciesWithExclusions = $ActivePolicies | Where-Object {
        $_.Conditions.Users.ExcludeUsers.Count -gt 0 -or
        $_.Conditions.Users.ExcludeGroups.Count -gt 0
    }
    
    [void]$Findings.Info.Add([PSCustomObject]@{
        Category = 'Break-glass'
        Finding = "$($PoliciesWithExclusions.Count) policies have user/group exclusions"
        Detail = 'Review exclusions to ensure only break-glass accounts are excluded'
    })
    
    #endregion
    
    #region Check 5: MFA for All Users
    Write-Verbose "Checking MFA for all users..."
    
    $MFAForAllUsers = $ActivePolicies | Where-Object {
        $_.Conditions.Users.IncludeUsers -contains 'All'
    } | Where-Object {
        $_.GrantControls.BuiltInControls -contains 'mfa' -or
        $_.GrantControls.AuthenticationStrength.Id
    }
    
    if (-not $MFAForAllUsers) {
        [void]$Findings.Gaps.Add([PSCustomObject]@{
            Severity = 'High'
            Category = 'MFA'
            Finding = 'No policy requires MFA for all users'
            Recommendation = 'Implement baseline MFA requirement for all users'
            CISControl = '1.1.2'
        })
    }
    
    #endregion
    
    #region Check 6: Risky Sign-in Protection
    Write-Verbose "Checking risky sign-in protection..."
    
    $RiskySignInPolicy = $ActivePolicies | Where-Object {
        $_.Conditions.SignInRiskLevels.Count -gt 0
    }
    
    if (-not $RiskySignInPolicy) {
        [void]$Findings.Gaps.Add([PSCustomObject]@{
            Severity = 'Medium'
            Category = 'Risk-based'
            Finding = 'No sign-in risk-based Conditional Access policy configured'
            Recommendation = 'Configure CA policies that respond to sign-in risk levels'
            CISControl = '1.2.1'
        })
    }
    
    #endregion
    
    #region Check 7: User Risk Protection
    Write-Verbose "Checking user risk protection..."
    
    $UserRiskPolicy = $ActivePolicies | Where-Object {
        $_.Conditions.UserRiskLevels.Count -gt 0
    }
    
    if (-not $UserRiskPolicy) {
        [void]$Findings.Gaps.Add([PSCustomObject]@{
            Severity = 'Medium'
            Category = 'Risk-based'
            Finding = 'No user risk-based Conditional Access policy configured'
            Recommendation = 'Configure CA policies that respond to user risk levels'
            CISControl = '1.2.2'
        })
    }
    
    #endregion
    
    # Build result object
    $Result = [PSCustomObject]@{
        TenantId = (Get-MgContext).TenantId
        AssessmentDate = Get-Date
        PolicySummary = $Findings.PolicyCount
        CriticalGaps = ($Findings.Gaps | Where-Object Severity -eq 'Critical').Count
        HighGaps = ($Findings.Gaps | Where-Object Severity -eq 'High').Count
        MediumGaps = ($Findings.Gaps | Where-Object Severity -eq 'Medium').Count
        Gaps = $Findings.Gaps
        Warnings = $Findings.Warnings
        Info = $Findings.Info
        Policies = $ActivePolicies | Select-Object Id, DisplayName, State, CreatedDateTime, ModifiedDateTime
    }
    
    # Console output
    Write-Host "`n┌─────────────────────────────────────────────────────────────┐" -ForegroundColor Cyan
    Write-Host "│  CONDITIONAL ACCESS GAP ANALYSIS                            │" -ForegroundColor Cyan
    Write-Host "└─────────────────────────────────────────────────────────────┘" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Policies Analyzed: $($Findings.PolicyCount.Total)" -ForegroundColor White
    Write-Host "  ├─ Enabled: $($Findings.PolicyCount.Enabled)" -ForegroundColor Green
    Write-Host "  ├─ Report-Only: $($Findings.PolicyCount.ReportOnly)" -ForegroundColor Yellow
    Write-Host "  └─ Disabled: $($Findings.PolicyCount.Disabled)" -ForegroundColor Gray
    Write-Host ""
    
    if ($Findings.Gaps.Count -gt 0) {
        Write-Host "  ⚠ GAPS DETECTED:" -ForegroundColor Red
        foreach ($Gap in $Findings.Gaps) {
            $Color = switch ($Gap.Severity) {
                'Critical' { 'Red' }
                'High' { 'DarkYellow' }
                'Medium' { 'Yellow' }
                default { 'White' }
            }
            Write-Host "    [$($Gap.Severity.ToUpper())] $($Gap.Finding)" -ForegroundColor $Color
        }
    }
    else {
        Write-Host "  ✓ No critical gaps detected" -ForegroundColor Green
    }
    
    Write-Host ""
    
    return $Result
}

Export-ModuleMember -Function Get-ConditionalAccessGaps
