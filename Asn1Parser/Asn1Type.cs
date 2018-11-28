namespace SysadminsLV.Asn1Parser {
    /// <summary>
    /// Represents an enumeration of ASN.1 types that belong to UNIVERSAL class.
    /// </summary>
    public enum Asn1Type : byte {
        /// <summary>
        /// Reserved for BER.
        /// </summary>
        RESERVED            = 0,
        /// <summary>
        /// The boolean type, declared with the keyword <strong>BOOLEAN</strong>, whose two possible values are
        /// <strong>TRUE</strong> and <strong>FALSE</strong>.
        /// </summary>
        BOOLEAN				= 1,
        /// <summary>
        /// The integer type, declared in ASN.1 by the keyword <strong>INTEGER</strong>, which stand for any positive or negative
        /// integer whatever its length.
        /// <p>Note, however, that this set of values does not include singular values like +&#8734; or
        /// -&#8734;. These values are members of the REAL type</p></summary>
        INTEGER				= 2,
        /// <summary>
        /// The <strong>BIT STRING</strong> is used to transmit data that are inherently binary (a compressed facsimile
        /// or encrypted data, for example) or to model boolean vectors (a list of choices in an MMI window. The BIT STRING
        /// type should be used only when it is absolutely necessary.
        /// <p>The binary string can be of null length or arbitrarily long.</p></summary>
        BIT_STRING			= 3,
        /// <summary>
        /// In ASN.1, an octet string, like a binary string, can be arbitrarily long.
        /// <p>Generally, the <strong>OCTET STRING</strong> type is used to transmit data that are intrinsically
        /// binary (which can be divided into 8-bit packets)</p></summary>
        OCTET_STRING		= 4,
        /// <summary>
        /// It contains a single value, the value <strong>NULL</strong> (note the ambiguity between the value
        /// notation and the type notation), which conveys only one piece of information (when the value gets
        /// through, the receiver knows what semantic should be associated with it).
        /// </summary>
        NULL				= 5,
        /// <summary>
        /// An object identifier is an identifier used to name an object (compare URN). Structurally, an OID consists of
        /// a node in a hierarchically-assigned namespace, formally defined using the ITU-T's ASN.1 standard.
        /// Successive numbers of the nodes, starting at the root of the tree, identify each node in the tree. Designers
        /// set up new nodes by registering them under the node's registration authority.
        /// </summary>
        OBJECT_IDENTIFIER	= 6,
        /// <summary>
        /// This string type is derived from the <strong>GraphicString</strong> and <strong>VisibleString</strong> types (see below).
        /// </summary>
        ObjectDescriptor	= 7,
        /// <summary>
        /// Type <strong>EXTERNAL</strong> takes values that communicate both data and how the data should be interpreted.
        /// The type of the data need not be an ASN.1 type. <strong>EXTERNAL</strong> is used, for example in the Association
        /// Control Service Element (ACSE) that is common to all OSI applications, to model a variable whose type is either
        /// unspecified or specified elsewhere. There is no restriction on the notation to specify the type.
        /// </summary>
        EXTERNAL			= 8,
        /// <summary>
        /// The real numbers are just like the other real numbers in information technology (decimals).
        /// <p>The type REAL in ASN.1 can model arbitrarily long but finite decimals.</p></summary>
        REAL				= 9,
        /// <summary>
        /// The type of enumerations is declared with the keyword ENUMERATED.
        /// <p>For an ENUMERATED type, a number is associated (implicitly or explicitly) with every
        /// identifier whereas, for an <see cref="INTEGER">INTEGER</see> type, an identifier is (explicitly) associated with each
        /// integer.</p></summary>
        ENUMERATED			= 10,
        /// <summary>
        /// <strong>Embedded PDV</strong> was created to carry any values, whether or not it is defined in ASN.1. This type
        /// has the ability to identify the type and the transfer syntax for the value being carried. ASN.1 has an associated
        /// type which must be referenced to create an <strong>Embedded PDV</strong> type.
        /// </summary>
        EMBEDDED_PDV		= 11,
        /// <summary>
        /// a variable format which encode ASCII characters on one octet (7 bits in fact) accordingly with the IA5 alphabet and
        /// the others in a sequence of two to six octets.
        /// </summary>
        UTF8String			= 12,
        /// <summary>
        /// <strong>RELATIVE-OID</strong> is used when many transmitted object identifiers denote objects registered in
        /// the same sub-tree of the registration tree. Otherwise said, all these identifiers relate to a common reference node.
        /// </summary>
        RELATIVE_OID		= 13,
        /// <summary>
        /// Models an ordered collection of variables of different type.
        /// </summary>
        SEQUENCE			= 16,
        /// <summary>
        /// Models an unordered collection of variables of different type.
        /// </summary>
        SET					= 17,
        /// <summary>
        /// Models data entered from such devices as telephone handsets. Numeric string may contain numeric characters
        /// 0-9 and space character (as per X.401).
        /// </summary>
        NumericString		= 18,
        /// <summary>
        /// <strong>PrintableString</strong> is an acceptable character set for the DirectoryName data type. PrintableString
        /// comprises a subset of the ASCII character set, and does not include the at sign (@) or ampersand (&amp;).
        /// <p>The corresponding alphabet consists of spaces, upper-case and lower-case letters, digits and the symbols
        /// "'", "(", ")","+", ",", "-", ".", "/", ":", "=" and "?"</p>
        /// </summary>
        PrintableString		= 19,
        /// <summary>
        /// The <strong>Teletex</strong> was designed as a 'super-telex' service for inter-connecting word-processing machines
        /// according to a page-based transmission mode with an alphabet of 308 characters.
        /// </summary>
        TeletexString		= 20,
        /// <summary>
        /// The Videotex system enables the user to visualize on a television screen or any equivalent terminal
        /// numerical text or graphical information transmitted on the telephone network (pseudographic).
        /// </summary>
        VideotexString		= 21,
        /// <summary>
        /// The '<strong>International Alphabet number 5</strong>' (or <strong>IA5</strong>) is based on 7-bit characters and
        /// was jointly published by ISO and ITU-T (1963). It has become the basic character set of most of the communicating
        /// systems. It is generally equivalent to the ASCII alphabet (international standard de-facto), but national versions,
        /// which can take into account accents or characters specific to some spoken languages may be proposed by national
        /// standardization organizations.
        /// </summary>
        IA5String			= 22,
        /// <summary>
        /// In case the flexibility offered by the various formats of the <strong>GeneralizedTime</strong> is not necessary,
        /// one may use the <strong>UTCTime</strong> type whose (more restricted) format is the following:
        /// <list type="number">
        /// <item> the calendar date with two digits for the year, two for the month and two for the day; and</item>
        /// <item> the hour, minutes and seconds; and</item>
        /// <item> either the capital letter 'Z' (Zulu) to indicate that the time is the UTC or a positive or negative delay
        /// with respect to the UTC.</item>
        /// </list>
        /// </summary>
        UTCTime				= 23,
        /// <summary>
        /// An extended representation of the Universal Coordinated Time. This format can remove interpretation ambiguities
        /// of a notation such as 5/12", which means 5th of December" in France and 12th of May" in Anglo-Saxon countries.
        /// A value of type <strong>GeneralizedTime</strong> is therefore made of:
        /// <list type="bullet">
        /// <item>the calendar date with four digits for the year, two for the month and two for an ordinal number standing
        /// for the day;</item>
        /// <item>the time with an hour, minute or second precision (or even fractions of a second) according to the precision
        /// of the communicating application;</item>
        /// <item>the indication of a possible time lag (the default is the local hour): if it is followed by the letter 'Z' (Zulu),
        /// it denotes the universal time as the coordinate (UTC); otherwise, the hour is followed by a positive or negative
        /// time lag expressed in hours and minutes whether it is ahead or behind the UTC.</item>
        /// </list>
        /// </summary>
        GeneralizedTime		= 24,
        /// <summary>
        /// A character string that can include spaces and any of the graphical (i.e. visible) character sets (called "G")
        /// registered in the 'International Register of Coded Character Sets to be used with Escape Sequences'.
        /// </summary>
        GraphicString		= 25,
        /// <summary>
        /// The ASN.1 character string type VisibleString encompasses all visible characters of the IA5String character set
        /// but do not include escape characters, newlines or any combination such as those for obtaining the accents with the
        /// backspace, for example.
        /// </summary>
        VisibleString		= 26,
        /// <summary>
        /// GeneralString type is based on all the character sets of the <strong>GraphicString</strong> type described
        /// above and includes all the control character sets (called "C"). Today, its use is not recommended.
        /// </summary>
        GeneralString		= 27,
        /// <summary>
        /// Universal string can contain characters from all the alphabets of all the languages on Earth. Each character
        /// is encoded by using 4 bytes.
        /// </summary>
        /// <remarks>The character set is stratified into 128 groups of 256 planes of 256 rows of 256 cells (i.e. an
        /// encoding of four bytes at most for each cell). At the moment, only the first plane (38,885 cells), called
        /// Basic Multilingual Plane or BMP, is allocated (see below BMPString).</remarks>
        UniversalString		= 28,
        /// <summary>
        /// The <strong>CHARACTER STRING</strong> type is the concrete application of the <strong>EMBEDDED PDV</strong> type
        /// to the special case of a character string.
        /// </summary>
        CHARACTER_STRING	= 29,
        /// <summary>
        /// It is useless to encode each character on four bytes since the first two bytes are systematically null and
        /// all remaining 65,536 cells belong to the first plane (group 0, plane 0) called Basic Multilingual Plane (BMP).
        /// This encoding on two bytes is called UCS-2.
        /// </summary>
        BMPString			= 30,
        /// <summary>
        /// TAG_MASK
        /// </summary>
        TAG_MASK			= 31,
    }
}
