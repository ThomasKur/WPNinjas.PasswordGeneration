Function Invoke-SecurePasswordGeneration(){
    <#
    .DESCRIPTION
    This method will return a dynamically generated password as SecureString. 

    .EXAMPLE
    $d = Invoke-SecurePasswordGeneration -Length 16
    $d 

    hjbs87a6!uUas212

    $d = Invoke-SecurePasswordGeneration -Length 12 -AllowedCharacters "ABCDEFGH"
    $d 

    ACGABHEABDFF

    .PARAMETER Length
        This value defines the length of the generated password. If none is provided 16 is used.

    .PARAMETER AllowedCharacters
        All characters in this string are allowed as characters during password generation. If no characters are defined the following default set will be used "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz.:;,-_!?$%*=+&<>@#()23456789".

    .PARAMETER CheckComplexity
        If set the password will regenerated until it contains characters from at least 3 groups out of 4 (Uper/Lower/Number/SpecialChar)

    .NOTES
    Author: Thomas Kurth/baseVISION
    Date:   13.6.2021

    History
        See Release Notes in Github.

    #>
    [CmdletBinding()]
    [OutputType([SecureString])]
    Param(
        [Parameter(Mandatory=$false)]
        [int]$Length = 16,
        [Parameter(Mandatory=$false)]
        [String]$AllowedCharacters = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz.:;,-_!?$%*=+&<>@#()23456789",
        [Switch]$RequireComplexity
    )
      

    #region Initialization
    ########################################################
    Write-Log "Start Script $Scriptname"
    #endregion

    #region Main Script
    ########################################################
    
    if($RequireComplexity){
        [WPNinjas.PasswordGeneration.PwService]::GetRandomPasswordSecure($Length,$AllowedCharacters)
    } else {
        [WPNinjas.PasswordGeneration.PwService]::GetRandomComplexPasswordSecure($Length,$AllowedCharacters)
    }

    #endregion
    #region Finishing
    ########################################################

    Write-Log "End Script $Scriptname"
    #endregion
}