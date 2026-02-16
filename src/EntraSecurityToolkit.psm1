#Requires -Version 5.1
<#
.SYNOPSIS
    Entra Security Toolkit - Microsoft Entra ID & M365 Security Assessment Module

.DESCRIPTION
    Comprehensive security assessment, auditing, and hardening toolkit for 
    Microsoft Entra ID (Azure AD) and Microsoft 365 environments.
    Supports both cloud-only and hybrid Active Directory scenarios.

.NOTES
    Author: Nick Lucker
    Version: 0.1.0
#>

# Module-level variables
$Script:ModuleRoot = $PSScriptRoot
$Script:IsConnected = $false
$Script:TenantInfo = $null

#region Module Initialization

# Import Classes
$ClassFiles = Get-ChildItem -Path "$ModuleRoot\Classes\*.ps1" -ErrorAction SilentlyContinue
foreach ($Class in $ClassFiles) {
    try {
        . $Class.FullName
        Write-Verbose "Imported class: $($Class.BaseName)"
    }
    catch {
        Write-Error "Failed to import class $($Class.FullName): $_"
    }
}

# Import Private Functions
$PrivateFunctions = Get-ChildItem -Path "$ModuleRoot\Private\*.ps1" -Recurse -ErrorAction SilentlyContinue
foreach ($Function in $PrivateFunctions) {
    try {
        . $Function.FullName
        Write-Verbose "Imported private function: $($Function.BaseName)"
    }
    catch {
        Write-Error "Failed to import private function $($Function.FullName): $_"
    }
}

# Import Public Functions
$PublicFunctions = Get-ChildItem -Path "$ModuleRoot\Public\*.ps1" -Recurse -ErrorAction SilentlyContinue
foreach ($Function in $PublicFunctions) {
    try {
        . $Function.FullName
        Write-Verbose "Imported public function: $($Function.BaseName)"
    }
    catch {
        Write-Error "Failed to import public function $($Function.FullName): $_"
    }
}

#endregion

#region Core Functions

function Connect-EntraSecurityToolkit {
    <#
    .SYNOPSIS
        Connects to Microsoft Graph with required permissions for security assessment.
    
    .DESCRIPTION
        Establishes a connection to Microsoft Graph API with the scopes required
        for running security assessments. Validates the connection and caches tenant info.
    
    .PARAMETER Scopes
        Additional scopes to request beyond the defaults.
    
    .PARAMETER TenantId
        Specific tenant ID to connect to (for multi-tenant scenarios).
    
    .EXAMPLE
        Connect-EntraSecurityToolkit
        
    .EXAMPLE
        Connect-EntraSecurityToolkit -TenantId "contoso.onmicrosoft.com"
    #>
    [CmdletBinding()]
    param(
        [string[]]$Scopes,
        [string]$TenantId
    )
    
    $DefaultScopes = @(
        "Directory.Read.All"
        "Policy.Read.All"
        "RoleManagement.Read.All"
        "Application.Read.All"
        "AuditLog.Read.All"
        "SecurityEvents.Read.All"
        "IdentityRiskyUser.Read.All"
        "IdentityRiskEvent.Read.All"
    )
    
    $AllScopes = $DefaultScopes + $Scopes | Select-Object -Unique
    
    $ConnectParams = @{
        Scopes = $AllScopes
        NoWelcome = $true
    }
    
    if ($TenantId) {
        $ConnectParams['TenantId'] = $TenantId
    }
    
    try {
        Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
        Connect-MgGraph @ConnectParams
        
        # Validate connection and get tenant info
        $Script:TenantInfo = Get-MgOrganization
        $Script:IsConnected = $true
        
        Write-Host "✓ Connected to tenant: $($Script:TenantInfo.DisplayName)" -ForegroundColor Green
        Write-Host "  Tenant ID: $($Script:TenantInfo.Id)" -ForegroundColor Gray
        
        return $true
    }
    catch {
        Write-Error "Failed to connect to Microsoft Graph: $_"
        $Script:IsConnected = $false
        return $false
    }
}

function Invoke-EntraSecurityAssessment {
    <#
    .SYNOPSIS
        Runs a comprehensive Entra ID security assessment.
    
    .DESCRIPTION
        Executes all security assessment modules and generates a consolidated report.
        Covers Conditional Access, Privileged Access, App Registrations, Sign-in Analysis,
        Security Baseline, and Hybrid Sync (if applicable).
    
    .PARAMETER OutputPath
        Directory to save the assessment report.
    
    .PARAMETER Modules
        Specific modules to run. Default is all modules.
    
    .PARAMETER SkipHybrid
        Skip hybrid sync checks (for cloud-only environments).
    
    .PARAMETER Format
        Output format: HTML, JSON, CSV, or Console.
    
    .EXAMPLE
        Invoke-EntraSecurityAssessment -OutputPath "./reports"
        
    .EXAMPLE
        Invoke-EntraSecurityAssessment -Modules @('ConditionalAccess', 'PrivilegedAccess') -Format HTML
    #>
    [CmdletBinding()]
    param(
        [string]$OutputPath = ".",
        
        [ValidateSet('All', 'ConditionalAccess', 'PrivilegedAccess', 'AppRegistrations', 
                     'SignInAnalysis', 'SecurityBaseline', 'HybridSync')]
        [string[]]$Modules = @('All'),
        
        [switch]$SkipHybrid,
        
        [ValidateSet('HTML', 'JSON', 'CSV', 'Console')]
        [string]$Format = 'Console'
    )
    
    # Validate connection
    if (-not $Script:IsConnected) {
        Write-Warning "Not connected to Microsoft Graph. Running Connect-EntraSecurityToolkit..."
        $Connected = Connect-EntraSecurityToolkit
        if (-not $Connected) {
            throw "Cannot run assessment without a valid connection."
        }
    }
    
    $AssessmentStart = Get-Date
    $Results = @{
        Metadata = @{
            TenantId = $Script:TenantInfo.Id
            TenantName = $Script:TenantInfo.DisplayName
            AssessmentDate = $AssessmentStart
            ToolkitVersion = '0.1.0'
        }
        ConditionalAccess = $null
        PrivilegedAccess = $null
        AppRegistrations = $null
        SignInAnalysis = $null
        SecurityBaseline = $null
        HybridSync = $null
        Summary = @{
            Critical = 0
            High = 0
            Medium = 0
            Low = 0
            Info = 0
        }
    }
    
    Write-Host "`n" -NoNewline
    Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║           ENTRA SECURITY ASSESSMENT                          ║" -ForegroundColor Cyan
    Write-Host "║           Tenant: $($Script:TenantInfo.DisplayName.PadRight(38))║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    
    # Run selected modules
    $ModulesToRun = if ($Modules -contains 'All') {
        @('ConditionalAccess', 'PrivilegedAccess', 'AppRegistrations', 'SignInAnalysis', 'SecurityBaseline')
        if (-not $SkipHybrid) { 'HybridSync' }
    } else {
        $Modules
    }
    
    foreach ($Module in $ModulesToRun) {
        Write-Host "[$Module] " -ForegroundColor Yellow -NoNewline
        Write-Host "Running assessment..." -ForegroundColor Gray
        
        # TODO: Implement individual module calls
        # $Results[$Module] = & "Get-$($Module)Assessment"
    }
    
    # Calculate summary
    $AssessmentEnd = Get-Date
    $Results.Metadata['Duration'] = $AssessmentEnd - $AssessmentStart
    
    Write-Host "`n✓ Assessment complete in $([math]::Round($Results.Metadata.Duration.TotalSeconds, 2)) seconds" -ForegroundColor Green
    
    # Output results
    switch ($Format) {
        'JSON' {
            $OutputFile = Join-Path $OutputPath "entra-assessment-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
            $Results | ConvertTo-Json -Depth 10 | Out-File $OutputFile
            Write-Host "Report saved to: $OutputFile" -ForegroundColor Cyan
        }
        'HTML' {
            # TODO: Implement HTML report generation
            Write-Warning "HTML output not yet implemented"
        }
        'CSV' {
            # TODO: Implement CSV export
            Write-Warning "CSV output not yet implemented"
        }
        default {
            # Console output handled above
        }
    }
    
    return $Results
}

#endregion

# Export module members (handled by manifest, but explicit for clarity)
Export-ModuleMember -Function @(
    'Connect-EntraSecurityToolkit'
    'Invoke-EntraSecurityAssessment'
)
