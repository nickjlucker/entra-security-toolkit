#Requires -Modules Pester

BeforeAll {
    # Import the module
    $ModulePath = Join-Path $PSScriptRoot '..' 'src' 'EntraSecurityToolkit.psd1'
    if (Test-Path $ModulePath) {
        Import-Module $ModulePath -Force
    }
    else {
        # Import function directly for testing
        . (Join-Path $PSScriptRoot '..' 'src' 'Public' 'ConditionalAccess' 'Get-ConditionalAccessCoverage.ps1')
    }
    
    # Mock data factory
    function New-MockPolicy {
        param(
            [string]$Id = [guid]::NewGuid().ToString(),
            [string]$DisplayName = "Test Policy",
            [string]$State = 'enabled',
            [string[]]$IncludeUsers = @(),
            [string[]]$ExcludeUsers = @(),
            [string[]]$IncludeGroups = @(),
            [string[]]$ExcludeGroups = @(),
            [string[]]$IncludeRoles = @(),
            [string[]]$IncludeApplications = @('All'),
            [string[]]$ExcludeApplications = @(),
            [string[]]$IncludePlatforms = @('all'),
            [string[]]$GrantControls = @('mfa')
        )
        
        return [PSCustomObject]@{
            Id = $Id
            DisplayName = $DisplayName
            State = $State
            Conditions = [PSCustomObject]@{
                Users = [PSCustomObject]@{
                    IncludeUsers = $IncludeUsers
                    ExcludeUsers = $ExcludeUsers
                    IncludeGroups = $IncludeGroups
                    ExcludeGroups = $ExcludeGroups
                    IncludeRoles = $IncludeRoles
                }
                Applications = [PSCustomObject]@{
                    IncludeApplications = $IncludeApplications
                    ExcludeApplications = $ExcludeApplications
                }
                Platforms = [PSCustomObject]@{
                    IncludePlatforms = $IncludePlatforms
                    ExcludePlatforms = @()
                }
                Locations = [PSCustomObject]@{
                    IncludeLocations = @()
                    ExcludeLocations = @()
                }
                SignInRiskLevels = @()
                UserRiskLevels = @()
            }
            GrantControls = [PSCustomObject]@{
                BuiltInControls = $GrantControls
                AuthenticationStrength = $null
            }
        }
    }
    
    function New-MockUser {
        param(
            [string]$Id = [guid]::NewGuid().ToString(),
            [string]$DisplayName = "Test User",
            [string]$UserPrincipalName = "test@contoso.com",
            [bool]$AccountEnabled = $true,
            [string]$UserType = "Member"
        )
        
        return [PSCustomObject]@{
            Id = $Id
            DisplayName = $DisplayName
            UserPrincipalName = $UserPrincipalName
            AccountEnabled = $AccountEnabled
            UserType = $UserType
        }
    }
    
    function New-MockServicePrincipal {
        param(
            [string]$Id = [guid]::NewGuid().ToString(),
            [string]$DisplayName = "Test App",
            [string]$AppId = [guid]::NewGuid().ToString()
        )
        
        return [PSCustomObject]@{
            Id = $Id
            DisplayName = $DisplayName
            AppId = $AppId
            ServicePrincipalType = "Application"
        }
    }
}

Describe 'Get-ConditionalAccessCoverage' {
    
    Context 'Mock Mode' {
        
        It 'Should run in mock mode without Graph connection' {
            $mockData = @{
                Policies = @(
                    New-MockPolicy -DisplayName "Require MFA for All" -IncludeUsers @('All')
                )
                Users = @(
                    New-MockUser -DisplayName "User 1"
                    New-MockUser -DisplayName "User 2"
                )
                Groups = @()
                ServicePrincipals = @(
                    New-MockServicePrincipal -DisplayName "App 1"
                )
                NamedLocations = @()
            }
            
            $result = Get-ConditionalAccessCoverage -MockData $mockData
            
            $result.MockMode | Should -BeTrue
            $result.TenantId | Should -Be 'mock-tenant'
        }
        
        It 'Should calculate 100% user coverage when All users targeted' {
            $mockData = @{
                Policies = @(
                    New-MockPolicy -DisplayName "All Users MFA" -IncludeUsers @('All')
                )
                Users = @(
                    New-MockUser -DisplayName "User 1"
                    New-MockUser -DisplayName "User 2"
                    New-MockUser -DisplayName "User 3"
                )
                Groups = @()
                ServicePrincipals = @()
                NamedLocations = @()
            }
            
            $result = Get-ConditionalAccessCoverage -MockData $mockData
            
            $result.UserCoverage.AllUsersTargeted | Should -BeTrue
            $result.UserCoverage.CoveragePercent | Should -Be 100
        }
        
        It 'Should account for excluded users in coverage calculation' {
            $excludedUserId = [guid]::NewGuid().ToString()
            
            $mockData = @{
                Policies = @(
                    New-MockPolicy -DisplayName "All Users Except Break-glass" -IncludeUsers @('All') -ExcludeUsers @($excludedUserId)
                )
                Users = @(
                    New-MockUser -DisplayName "User 1"
                    New-MockUser -DisplayName "User 2"
                    New-MockUser -Id $excludedUserId -DisplayName "Break-glass"
                )
                Groups = @()
                ServicePrincipals = @()
                NamedLocations = @()
            }
            
            $result = Get-ConditionalAccessCoverage -MockData $mockData
            
            $result.UserCoverage.ExcludedUsersCount | Should -Be 1
            $result.UserCoverage.CoveredUsers | Should -Be 2
            # 2 out of 3 = 66.7%
            $result.UserCoverage.CoveragePercent | Should -BeGreaterThan 60
            $result.UserCoverage.CoveragePercent | Should -BeLessThan 70
        }
        
        It 'Should detect all apps targeted' {
            $mockData = @{
                Policies = @(
                    New-MockPolicy -DisplayName "All Apps" -IncludeUsers @('All') -IncludeApplications @('All')
                )
                Users = @()
                Groups = @()
                ServicePrincipals = @(
                    New-MockServicePrincipal -DisplayName "App 1"
                    New-MockServicePrincipal -DisplayName "App 2"
                )
                NamedLocations = @()
            }
            
            $result = Get-ConditionalAccessCoverage -MockData $mockData
            
            $result.AppCoverage.AllAppsTargeted | Should -BeTrue
        }
        
        It 'Should detect Office 365 apps targeted' {
            $mockData = @{
                Policies = @(
                    New-MockPolicy -DisplayName "Office Apps" -IncludeUsers @('All') -IncludeApplications @('Office365')
                )
                Users = @()
                Groups = @()
                ServicePrincipals = @()
                NamedLocations = @()
            }
            
            $result = Get-ConditionalAccessCoverage -MockData $mockData
            
            $result.AppCoverage.OfficeAppsTargeted | Should -BeTrue
        }
        
        It 'Should count grant controls correctly' {
            $mockData = @{
                Policies = @(
                    New-MockPolicy -DisplayName "MFA Policy" -IncludeUsers @('All') -GrantControls @('mfa')
                    New-MockPolicy -DisplayName "Block Legacy" -IncludeUsers @('All') -GrantControls @('block')
                    New-MockPolicy -DisplayName "Compliance" -IncludeUsers @('All') -GrantControls @('compliantDevice')
                )
                Users = @()
                Groups = @()
                ServicePrincipals = @()
                NamedLocations = @()
            }
            
            $result = Get-ConditionalAccessCoverage -MockData $mockData
            
            $result.ControlCoverage.MFA.Enforced | Should -Be 1
            $result.ControlCoverage.Block.Enforced | Should -Be 1
            $result.ControlCoverage.CompliantDevice.Enforced | Should -Be 1
        }
        
        It 'Should distinguish enforced vs report-only policies' {
            $mockData = @{
                Policies = @(
                    New-MockPolicy -DisplayName "Enforced MFA" -State 'enabled' -IncludeUsers @('All') -GrantControls @('mfa')
                    New-MockPolicy -DisplayName "Report-Only MFA" -State 'enabledForReportingButNotEnforced' -IncludeUsers @('All') -GrantControls @('mfa')
                )
                Users = @()
                Groups = @()
                ServicePrincipals = @()
                NamedLocations = @()
            }
            
            $result = Get-ConditionalAccessCoverage -MockData $mockData
            
            $result.PolicySummary.Enabled | Should -Be 1
            $result.PolicySummary.ReportOnly | Should -Be 1
            $result.ControlCoverage.MFA.Enforced | Should -Be 1
            $result.ControlCoverage.MFA.ReportOnly | Should -Be 1
        }
        
        It 'Should exclude disabled policies by default' {
            $mockData = @{
                Policies = @(
                    New-MockPolicy -DisplayName "Enabled" -State 'enabled' -IncludeUsers @('All')
                    New-MockPolicy -DisplayName "Disabled" -State 'disabled' -IncludeUsers @('All')
                )
                Users = @()
                Groups = @()
                ServicePrincipals = @()
                NamedLocations = @()
            }
            
            $result = Get-ConditionalAccessCoverage -MockData $mockData
            
            $result.PolicySummary.Total | Should -Be 2
            $result.PolicySummary.Enabled | Should -Be 1
            $result.PolicySummary.Disabled | Should -Be 1
        }
        
        It 'Should include disabled policies when specified' {
            $mockData = @{
                Policies = @(
                    New-MockPolicy -DisplayName "Enabled" -State 'enabled' -IncludeUsers @('All') -GrantControls @('mfa')
                    New-MockPolicy -DisplayName "Disabled" -State 'disabled' -IncludeUsers @('All') -GrantControls @('mfa')
                )
                Users = @()
                Groups = @()
                ServicePrincipals = @()
                NamedLocations = @()
            }
            
            $result = Get-ConditionalAccessCoverage -MockData $mockData -IncludeDisabled
            
            # When IncludeDisabled, the disabled policy should also be counted in control coverage
            $result.ControlCoverage.MFA.Enforced | Should -Be 2
        }
        
        It 'Should calculate platform coverage' {
            $mockData = @{
                Policies = @(
                    New-MockPolicy -DisplayName "Windows/iOS Only" -IncludeUsers @('All') -IncludePlatforms @('windows', 'iOS')
                )
                Users = @()
                Groups = @()
                ServicePrincipals = @()
                NamedLocations = @()
            }
            
            $result = Get-ConditionalAccessCoverage -MockData $mockData
            
            $result.PlatformCoverage.Platforms['windows'].Included | Should -BeTrue
            $result.PlatformCoverage.Platforms['iOS'].Included | Should -BeTrue
            $result.PlatformCoverage.Platforms['android'].Included | Should -BeFalse
        }
        
        It 'Should return detailed data when requested' {
            $mockData = @{
                Policies = @(
                    New-MockPolicy -DisplayName "Test Policy" -IncludeUsers @('All')
                )
                Users = @()
                Groups = @()
                ServicePrincipals = @()
                NamedLocations = @()
            }
            
            $result = Get-ConditionalAccessCoverage -MockData $mockData -Detailed
            
            $result.Policies | Should -Not -BeNullOrEmpty
            $result.Policies[0].DisplayName | Should -Be "Test Policy"
        }
    }
    
    Context 'Edge Cases' {
        
        It 'Should handle empty policy list' {
            $mockData = @{
                Policies = @()
                Users = @(New-MockUser)
                Groups = @()
                ServicePrincipals = @()
                NamedLocations = @()
            }
            
            $result = Get-ConditionalAccessCoverage -MockData $mockData
            
            $result.PolicySummary.Total | Should -Be 0
            $result.UserCoverage.CoveragePercent | Should -Be 0
        }
        
        It 'Should handle empty user list' {
            $mockData = @{
                Policies = @(New-MockPolicy -IncludeUsers @('All'))
                Users = @()
                Groups = @()
                ServicePrincipals = @()
                NamedLocations = @()
            }
            
            $result = Get-ConditionalAccessCoverage -MockData $mockData
            
            $result.UserCoverage.TotalUsers | Should -Be 0
            $result.UserCoverage.CoveragePercent | Should -Be 0
        }
        
        It 'Should calculate overall score' {
            $mockData = @{
                Policies = @(
                    New-MockPolicy -DisplayName "Full Coverage" -IncludeUsers @('All') -IncludeApplications @('All') -IncludePlatforms @('all') -GrantControls @('mfa')
                )
                Users = @(
                    New-MockUser -DisplayName "User 1"
                    New-MockUser -DisplayName "User 2"
                )
                Groups = @()
                ServicePrincipals = @(
                    New-MockServicePrincipal -DisplayName "App 1"
                )
                NamedLocations = @()
            }
            
            $result = Get-ConditionalAccessCoverage -MockData $mockData
            
            $result.OverallCoverageScore | Should -BeGreaterThan 0
            $result.OverallCoverageScore | Should -BeLessOrEqual 100
        }
    }
    
    Context 'Security Scenarios' {
        
        It 'Should identify high-coverage baseline (MFA for all, block legacy)' {
            $mockData = @{
                Policies = @(
                    New-MockPolicy -DisplayName "Require MFA for All Users" -IncludeUsers @('All') -IncludeApplications @('All') -GrantControls @('mfa')
                    New-MockPolicy -DisplayName "Block Legacy Auth" -IncludeUsers @('All') -IncludeApplications @('All') -GrantControls @('block')
                )
                Users = 1..100 | ForEach-Object { New-MockUser -DisplayName "User $_" }
                Groups = @()
                ServicePrincipals = @()
                NamedLocations = @()
            }
            
            $result = Get-ConditionalAccessCoverage -MockData $mockData
            
            $result.UserCoverage.CoveragePercent | Should -Be 100
            $result.ControlCoverage.MFA.Enforced | Should -BeGreaterThan 0
            $result.ControlCoverage.Block.Enforced | Should -BeGreaterThan 0
        }
        
        It 'Should identify global admin role targeting' {
            $GlobalAdminRoleId = '62e90394-69f5-4237-9190-012177145e10'
            
            $mockData = @{
                Policies = @(
                    New-MockPolicy -DisplayName "Require MFA for Admins" -IncludeRoles @($GlobalAdminRoleId) -GrantControls @('mfa')
                )
                Users = @()
                Groups = @()
                ServicePrincipals = @()
                NamedLocations = @()
            }
            
            $result = Get-ConditionalAccessCoverage -MockData $mockData
            
            $result.UserCoverage.RolesTargetedCount | Should -Be 1
        }
    }
}
