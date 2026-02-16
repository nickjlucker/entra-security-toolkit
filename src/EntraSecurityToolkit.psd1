@{
    # Module Info
    ModuleVersion        = '0.1.0'
    GUID                 = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
    Author               = 'Nick Lucker'
    CompanyName          = 'Community'
    Copyright            = '(c) 2026 Nick Lucker. All rights reserved.'
    Description          = 'Microsoft Entra ID & M365 Security Assessment, Auditing, and Hardening Toolkit'
    
    # Requirements
    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    
    # Module Components
    RootModule           = 'EntraSecurityToolkit.psm1'
    
    # Functions to export
    FunctionsToExport    = @(
        # Core
        'Invoke-EntraSecurityAssessment'
        'Connect-EntraSecurityToolkit'
        
        # Conditional Access
        'Get-ConditionalAccessGaps'
        'Get-ConditionalAccessCoverage'
        'Test-LegacyAuthBlocked'
        'Get-CABreakGlassExclusions'
        
        # Privileged Access
        'Get-PrivilegedRoleAudit'
        'Get-GlobalAdminReport'
        'Get-PIMStatus'
        'Get-StaleAdminAccounts'
        'Get-StandingPrivilegedAccess'
        
        # App Registrations
        'Get-RiskyAppRegistrations'
        'Get-OverpermissionedApps'
        'Get-ExpiredAppCredentials'
        'Get-UserConsentedApps'
        
        # Sign-in Analysis
        'Get-SignInRiskAnalysis'
        'Get-RiskySignIns'
        'Get-AuthenticationPatterns'
        
        # Security Baseline
        'Test-SecurityDefaults'
        'Test-CISBenchmark'
        'Get-SecurityBaselineCompliance'
        
        # Hybrid Sync
        'Get-HybridSyncHealth'
        'Get-AADConnectStatus'
        'Get-SyncErrors'
        'Get-PasswordSyncStatus'
    )
    
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    
    # Dependencies
    RequiredModules      = @(
        @{ModuleName = 'Microsoft.Graph.Authentication'; ModuleVersion = '2.0.0'}
        @{ModuleName = 'Microsoft.Graph.Identity.DirectoryManagement'; ModuleVersion = '2.0.0'}
        @{ModuleName = 'Microsoft.Graph.Identity.SignIns'; ModuleVersion = '2.0.0'}
        @{ModuleName = 'Microsoft.Graph.Applications'; ModuleVersion = '2.0.0'}
    )
    
    # Private Data
    PrivateData          = @{
        PSData = @{
            Tags         = @('Security', 'EntraID', 'AzureAD', 'M365', 'Identity', 'Assessment', 'Audit')
            LicenseUri   = 'https://github.com/nickjlucker/entra-security-toolkit/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/nickjlucker/entra-security-toolkit'
            ReleaseNotes = 'Initial release - v0.1.0'
        }
    }
}
