Function Invoke-PasswordGeneration(){
    <#
    .DESCRIPTION
    This method will return a dynamically generated password as String. Which is not as secure as the Invoke-SecurePasswordGeneration method.

    .EXAMPLE
    $d = Invoke-PasswordGeneration -Length 16
    $d 

    hjbs87a6!uUas212

    $d = Invoke-PasswordGeneration -Length 12 -AllowedCharacters "ABCDEFGH"
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
    Date:   10.06.2022

    History
        See Release Notes in Github.
        10.6.2022: Add COmplexity Check

    #>
    [CmdletBinding()]
    [OutputType([String])]
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
        [WPNinjas.PasswordGeneration.PwService]::GetRandomComplexPassword($Length,$AllowedCharacters)
    } else {
        [WPNinjas.PasswordGeneration.PwService]::GetRandomPassword($Length,$AllowedCharacters)
    }
    #endregion
    #region Finishing
    ########################################################

    Write-Log "End Script $Scriptname"
    #endregion
}