namespace SysadminsLV.Asn1Parser;

/// <summary>
/// Defines ASN.1 tagging classes.
/// </summary>
public enum Asn1Class : System.Byte {
    /// <summary>
    /// Represents Universal tag class.
    /// </summary>
    UNIVERSAL        = 0,    // 0x00
    /// <summary>
    /// Represents Constructed tag class.
    /// </summary>
    CONSTRUCTED      = 32,    // 0x20
    /// <summary>
    /// Represents Application tag class.
    /// </summary>
    APPLICATION      = 64,    // 0x40
    /// <summary>
    /// <strong>CONTEXT-SPECIFIC</strong> distinguishes members of a sequence or set, the alternatives of a CHOICE, or
    /// universally tagged set members.
    /// </summary>
    CONTEXT_SPECIFIC = 128,    // 0x80
    /// <summary>
    /// Represents Private tag class.
    /// </summary>
    PRIVATE          = 192    // 0xc0
}