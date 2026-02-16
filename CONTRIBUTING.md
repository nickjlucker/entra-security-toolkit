# Contributing to Entra Security Toolkit

Thank you for your interest in contributing! This document provides guidelines and information for contributors.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR-USERNAME/entra-security-toolkit.git`
3. Create a feature branch: `git checkout -b feature/your-feature-name`
4. Make your changes
5. Test thoroughly
6. Submit a pull request

## Development Setup

### Prerequisites

- PowerShell 5.1+ (7+ recommended for development)
- Microsoft Graph PowerShell SDK
- Pester (for running tests)

```powershell
# Install dependencies
Install-Module -Name Microsoft.Graph -Scope CurrentUser
Install-Module -Name Pester -Scope CurrentUser -MinimumVersion 5.0
```

### Running Tests

```powershell
# Run all tests
Invoke-Pester ./tests

# Run specific test file
Invoke-Pester ./tests/ConditionalAccess.Tests.ps1
```

## Code Style Guidelines

### PowerShell Best Practices

- Use approved verbs (Get-, Set-, New-, etc.)
- Include comprehensive comment-based help
- Use `[CmdletBinding()]` on all functions
- Support `-Verbose` and `-Debug` parameters
- Return structured objects, not formatted text

### Function Structure

```powershell
function Verb-Noun {
    <#
    .SYNOPSIS
        Brief description.
    
    .DESCRIPTION
        Detailed description.
    
    .PARAMETER ParameterName
        Parameter description.
    
    .EXAMPLE
        Verb-Noun -ParameterName Value
        
        Description of example.
    
    .OUTPUTS
        Type. Description.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ParameterName
    )
    
    # Implementation
}
```

### Naming Conventions

- Functions: `Verb-EntraSecurityNoun`
- Variables: `$PascalCase`
- Private functions: Prefix with underscore or place in Private folder

## Pull Request Process

1. Update documentation for any new features
2. Add or update tests as needed
3. Ensure all tests pass
4. Update the changelog
5. Request review from maintainers

## Security Considerations

- Never commit credentials or secrets
- Use `SecureString` for sensitive parameters
- Follow least-privilege principles in examples
- Test against non-production environments

## Reporting Security Vulnerabilities

If you discover a security vulnerability, please:
1. **Do NOT** open a public issue
2. Email the maintainers directly
3. Provide detailed reproduction steps

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
