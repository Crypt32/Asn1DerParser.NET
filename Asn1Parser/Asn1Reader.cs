using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using SysadminsLV.Asn1Parser.Universal;
using SysadminsLV.Asn1Parser.Utils;

namespace SysadminsLV.Asn1Parser;

/// <summary>
/// Provides a set of properties and generic methods to work with ASN.1 structures in Distinguished Encoding
/// Rules (<strong>DER</strong>) encoding.
/// </summary>
public class Asn1Reader {
    // a list of primitive tags. Source: http://en.wikipedia.org/wiki/Distinguished_Encoding_Rules#DER_encoding
    // although we actively do lookups, it is NOT recommended to use sets (HashSet<T>), because at current collection size
    // lookups in HashSet are around 3-4x times slower than in plain list.
    static readonly List<Byte> _excludedTags = [ 0, 1, 2, 5, 6, 9, 10, 12, 13, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30 ];
    static readonly List<Byte> _multiNestedTypes = [
        (Byte)Asn1Type.SEQUENCE,
        (Byte)Asn1Type.SEQUENCE | (Byte)Asn1Class.CONSTRUCTED,
        (Byte)Asn1Type.SET,
        (Byte)Asn1Type.SET | (Byte)Asn1Class.CONSTRUCTED
    ];
    ReadOnlyMemory<Byte> _rawData;
    readonly Dictionary<Int64, AsnInternalMap> _offsetMap = [];
    AsnInternalMap currentPosition;
    Int32 childCount;

    /// <summary>
    /// Initializes a new instance of the <strong>ASN1</strong> class from an existing
    /// <strong>ASN1</strong> object.
    /// </summary>
    /// <param name="asn">An existing <strong>ASN1</strong> object.</param>
    /// <remarks>
    ///		This constructor creates a copy of a current position of an existing <strong>ASN1</strong> object.
    /// </remarks>
    [Obsolete("Consider using 'GetReader()' method on existing instance.", true)]
    public Asn1Reader(Asn1Reader asn) : this(asn.GetTagRawDataAsMemory(), 0, true) { }
    /// <summary>
    /// Initializes a new instance of the <strong>ASN1</strong> class by using an ASN.1 encoded byte array.
    /// </summary>
    /// <param name="rawData">ASN.1-encoded byte array.</param>
    /// <exception cref="InvalidDataException">
    ///     The data in the <strong>rawData</strong> parameter is not valid ASN sequence.
    /// </exception>
    /// <remarks>
    ///     If <strong>rawData</strong> size is greater than outer structure size, constructor will take only
    ///     required bytes from input data.
    /// </remarks>
    public Asn1Reader(ReadOnlyMemory<Byte> rawData) : this(rawData, 0) { }

    Asn1Reader(ReadOnlyMemory<Byte> rawData, Int32 offset, Boolean skipCopy = false) {
        if (rawData.Length < 2) {
            throw new Win32Exception(ErrorCode.InvalidDataException);
        }
        currentPosition = new AsnInternalMap(0, 0);
        _offsetMap.Add(0, currentPosition);
        decode(rawData, offset, skipCopy);
    }

    /// <summary>
    /// Gets current position in the byte array stored in current data source.
    /// </summary>
    public Int32 Offset { get; private set; }
    /// <summary>
    /// Gets current structure's tag.
    /// </summary>
    public Byte Tag { get; private set; }
    /// <summary>
    /// Gets current structure tag name.
    /// </summary>
    public String TagName { get; private set; } = String.Empty;
    /// <summary>
    /// Gets current structure full length. Full length contains tag, tag length byte (or bytes) and tag payload.
    /// </summary>
    public Int32 TagLength { get; private set; }
    /// <summary>
    /// Gets a position at which current structure's payload starts (excluding tag and tag length byte (or bytes)).
    /// </summary>
    public Int32 PayloadStartOffset { get; private set; }
    /// <summary>
    /// Gets the length of the current structure's payload.
    /// </summary>
    public Int32 PayloadLength { get; private set; }
    /// <summary>
    /// Gets the internal ASN.1 stream length in bytes.
    /// </summary>
    public Int32 Length => _rawData.Length;
    /// <summary>
    /// Gets next structure's offset at same level (next sibling).
    /// </summary>
    public Int32 NextSiblingOffset { get; private set; }
    /// <summary>
    /// Gets next structure's offset. If current element is the last element in the data, the property returns zero.
    /// </summary>
    public Int32 NextOffset { get; private set; }
    /// <summary>
    /// Indicates whether the current tag is container, so it have children instead of explicit tag value.
    /// </summary>
    public Boolean IsConstructed { get; private set; }
    /// <summary>
    /// Gets access to internal binary raw data at specified index.
    /// </summary>
    /// <param name="index">Binary array index to access.</param>
    /// <exception cref="IndexOutOfRangeException"><strong>index</strong> parameter is outside of binary array boundaries.</exception>
    public Byte this[Int32 index] => _rawData.Span[index];

    void decode(ReadOnlyMemory<Byte> raw, Int32 pOffset, Boolean skipCopy = false) {
        IsConstructed = false;
        childCount = 0;
        if (!raw.IsEmpty) {
            if (skipCopy) {
                _rawData = raw;
            } else {
                _rawData = raw.ToArray();
            }
        }
        Offset = pOffset;
        Tag = _rawData.Span[Offset];
        calculateLength();
        // strip possible unnecessary bytes
        if (!raw.IsEmpty && TagLength != _rawData.Length) {
            _rawData = raw.Slice(0, TagLength).ToArray();
        }
        TagName = GetTagName(Tag);
        // 0 Tag is reserved for BER and is not available in DER
        if (Tag == 0) {
            throw new Asn1InvalidTagException(Offset);
        }
        // the idea is that SET/SEQUENCE and any explicitly constructed types are constructed by default.
        // Though, we need to limit them for Application and higher classes which are not guaranteed to be
        // constructed.
        if (_multiNestedTypes.Contains(Tag) || (Tag & (Byte)Asn1Class.CONSTRUCTED) > 0 && Tag < (Byte)Asn1Class.APPLICATION) {
            IsConstructed = true;
        }
        if (PayloadLength == 0) {
            // if current node is the last node in binary data, set NextOffset to 0, this means EOF.
            NextOffset = Offset + TagLength == _rawData.Length
                ? 0
                : Offset + TagLength;
            NextSiblingOffset = currentPosition.LevelEnd == 0 || Offset - currentPosition.LevelStart + TagLength == currentPosition.LevelEnd
                ? 0
                : NextOffset;
            return;
        }
        parseNestedType();
        NextSiblingOffset = Offset - currentPosition.LevelStart + TagLength < currentPosition.LevelEnd
            ? Offset + TagLength
            : 0;
        NextOffset = IsConstructed
            ? Tag == 3
                // skip unused bits byte
                ? PayloadStartOffset + 1
                : PayloadStartOffset
            : Offset + TagLength < _rawData.Length
                ? Offset + TagLength
                : 0;
    }
    void parseNestedType() {
        // processing rules (assuming zero-based bits):
        // -- if bit 5 is set to "1", or the type is SEQUENCE/SET -- the type is constructed. Unroll nested types.
        // -- if bit 5 is set to "0", attempt to resolve nested types only for UNIVERSAL tags.
        // -- if the value is implicitly tagged, it cannot contain nested types.
        // -- some universal types cannot include nested types: skip them in advance.
        if (_excludedTags.Contains(Tag) || PayloadLength < 2 || (Tag > 127 & Tag < 160)) {
            return;
        }
        Int64 start = PayloadStartOffset;
        Int32 length = PayloadLength;
        // BIT_STRING includes "unused bits" octet, do not count it in calculations
        if (Tag == (Byte)Asn1Type.BIT_STRING) {
            start = PayloadStartOffset + 1;
            length = PayloadLength - 1;
        }
        // if current type is constructed or nestable by default
        if (IsConstructed) {
            // check if map for current type exists
            if (!_offsetMap.ContainsKey(start)) {
                // if current map doesn't contain nested types boundaries, add them to the map.
                // this condition occurs when we face current type for the first time.
                predict(start, length, true, out childCount);
            } else {
                predict(start, length, false, out childCount);
            }
            return;
        }
        // universal types can contain only universal or constructed nested types.
        if (Tag < (Byte)Asn1Type.TAG_MASK && !testNestedForUniversal(start, length)) {
            return;
        }
        // attempt to unroll nested type
        IsConstructed = predict(start, length, false, out childCount);
        // reiterate again and build map for children
        if (IsConstructed && !_offsetMap.ContainsKey(start)) {
            predict(start, length, true, out childCount);
        }
    }
    Boolean validateArrayBoundaries(Int64 start) {
        if (start > Int32.MaxValue) {
            return false;
        }
        return start >= 0 && start < _rawData.Length && _rawData.Span[(Int32)start] != 0;
    }
    /// <summary>
    /// Checks if current primitive type is sub-typed (contains nested types) or not.
    /// </summary>
    /// <param name="start">Offset position where suggested nested type is expected.</param>
    /// <param name="estimatedLength">
    ///     Specifies the full length (including header) of suggested nested type.
    /// </param>
    /// <returns>
    /// <strong>True</strong> if current type has proper single nested type, otherwise <strong>False</strong>.
    /// </returns>
    Boolean testNestedForUniversal(Int64 start, Int32 estimatedLength) {
        if (start > Int32.MaxValue) {
            return false;
        }
        // if current type is primitive, then nested type can be either, primitive or constructed only.
        if (_rawData.Span[(Int32)start] >= (Byte)Asn1Class.APPLICATION) {
            return false;
        }
        // otherwise, attempt to resolve nested type. Only single nested type is allowed for primitive types.
        // Multiple types are not allowed.

        // sanity check for array boundaries
        if (!validateArrayBoundaries(start)) {
            return false;
        }
        // calculate length for nested type
        Int64 pl = calculatePredictLength(start);
        // and it must match the estimated length
        return pl == estimatedLength;
    }
    Boolean predict(Int64 start, Int32 projectedLength, Boolean assignMap, out Int32 estimatedChildCount) {
        Int64 levelStart = start;
        Int64 sum = 0;
        estimatedChildCount = 0;
        do {
            if (!validateArrayBoundaries(start)) {
                return false;
            }
            Int64 pl = calculatePredictLength(start);
            sum += pl;
            if (assignMap && sum <= projectedLength) {
                _offsetMap.Add(start, new AsnInternalMap(levelStart, projectedLength));
            }
            start += pl;
            estimatedChildCount++;
        } while (sum < projectedLength);
        if (sum != projectedLength) { estimatedChildCount = 0; }
        return sum == projectedLength;
    }
    void calculateLength() {
        if (_rawData.Span[Offset + 1] < 128) {
            PayloadStartOffset = Offset + 2;
            PayloadLength = _rawData.Span[Offset + 1];
            TagLength = PayloadLength + 2;
        } else {
            Int32 lengthBytes = _rawData.Span[Offset + 1] - 128;
            // max length can be encoded by using 4 bytes.
            if (lengthBytes > 4) {
                throw new OverflowException("Data length is too large.");
            }
            PayloadStartOffset = Offset + 2 + lengthBytes;
            PayloadLength = _rawData.Span[Offset + 2];
            for (Int32 i = Offset + 3; i < PayloadStartOffset; i++) {
                PayloadLength = (PayloadLength << 8) | _rawData.Span[i];
            }
            TagLength = PayloadLength + lengthBytes + 2;
        }
    }
    /// <summary>
    /// Calculates the length for suggested nested type.
    /// </summary>
    /// <param name="offset">Start offset for suggested nested type.</param>
    /// <returns>Estimated full tag length for nested type.</returns>
    Int64 calculatePredictLength(Int64 offset) {
        if (offset + 1 >= _rawData.Length || offset < 0) {
            return Int32.MaxValue;
        }

        if (_rawData.Span[(Int32)(offset + 1)] < 128) {
            return _rawData.Span[(Int32) (offset + 1)] + 2;
        }
        Int32 lengthBytes = _rawData.Span[(Int32)(offset + 1)] - 128;
        // max length can be encoded by using 4 bytes.
        if (lengthBytes > 4 || offset + 2 >= _rawData.Length) {
            return Int32.MaxValue;
        }
        Int32 pPayloadLength = _rawData.Span[(Int32)(offset + 2)];
        for (Int32 i = (Int32)(offset + 3); i < offset + 2 + lengthBytes; i++) {
            pPayloadLength = (pPayloadLength << 8) | _rawData.Span[i];
        }
        // 2 -- transitional + tag
        return pPayloadLength + lengthBytes + 2;
    }
    void moveAndExpectTypes(Func<Boolean> action, params Byte[] expectedTypes) {
        if (expectedTypes is null) {
            throw new ArgumentNullException(nameof(expectedTypes));
        }
        var set = new HashSet<Byte>();
        foreach (Byte tag in expectedTypes) {
            set.Add(tag);
        }
        if (!action.Invoke()) {
            throw new InvalidDataException("The data is invalid.");
        }

        if (!set.Contains(Tag)) {
            throw new Asn1InvalidTagException();
        }
    }

    /// <summary>
    /// Gets current structure header. Header contains tag and tag length byte (or bytes).
    /// </summary>
    /// <returns>Current structure header. Header contains tag and tag length byte (or bytes).</returns>
    public Byte[] GetHeader() {
        Int32 headerLength = PayloadStartOffset - Offset;
        Byte[] array = new Byte[headerLength];
        for (Int32 i = 0; i < headerLength; i++) {
            array[i] = _rawData.Span[Offset + i];
        }

        return array;
    }
    /// <summary>
    /// Gets current structure header. Header contains tag and tag length byte (or bytes).
    /// </summary>
    /// <returns>Current structure header. Header contains tag and tag length byte (or bytes).</returns>
    public ReadOnlyMemory<Byte> GetHeaderAsMemory() {
        Int32 headerLength = PayloadStartOffset - Offset;

        return _rawData.Slice(Offset, headerLength);
    }
    /// <summary>
    /// Gets the byte array of the current structure's payload.
    /// </summary>
    /// <returns>Byte array of the current structure's payload</returns>
    public Byte[] GetPayload() {
        Byte[] array = new Byte[PayloadLength];
        for (Int32 i = 0; i < PayloadLength; i++) {
            array[i] = _rawData.Span[PayloadStartOffset + i];
        }
        return array;
    }
    /// <summary>
    /// Gets the byte array of the current structure's payload.
    /// </summary>
    /// <returns>Memory span of the current structure's payload.</returns>
    public ReadOnlyMemory<Byte> GetPayloadAsMemory() {
        return _rawData.Slice(PayloadStartOffset, PayloadLength);
    }
    /// <summary>
    /// Gets the raw data of the tag, which includes tag, length bytes and payload.
    /// </summary>
    /// <returns>A full binary copy of the tag.</returns>
    public Byte[] GetTagRawData() {
        Byte[] array = new Byte[TagLength];
        for (Int32 i = 0; i < TagLength; i++) {
            array[i] = _rawData.Span[Offset + i];
        }
        return array;
    }
    /// <summary>
    /// Gets the raw data of the tag, which includes tag, length bytes and payload.
    /// </summary>
    /// <returns>A full binary copy of the tag.</returns>
    public ReadOnlyMemory<Byte> GetTagRawDataAsMemory() {
        return _rawData.Slice(Offset, TagLength);
    }
    /// <summary>
    /// Gets a copy of internal ASN.1 stream. The size of the stream is equals to <see cref="Length"/> member value.
    /// </summary>
    /// <returns>A full binary copy of the internal byte stream.</returns>
    public Byte[] GetRawData() {
        Byte[] array = new Byte[_rawData.Length];
        for (Int32 i = 0; i < _rawData.Length; i++) {
            array[i] = _rawData.Span[i];
        }
        return array;
    }
    /// <summary>
    /// Gets a copy of internal ASN.1 stream. The size of the stream is equals to <see cref="Length"/> member value.
    /// </summary>
    /// <returns>A full binary copy of the internal byte stream.</returns>
    public ReadOnlyMemory<Byte> GetRawDataAsMemory() {
        return _rawData;
    }
    /// <summary>
    /// Gets the count of nested nodes under node in the current position.
    /// </summary>
    /// <returns>Count of nested nodes.</returns>
    /// <remarks>For primitive types and empty containers this method returns 0.</remarks>
    public Int32 GetNestedNodeCount() {
        return IsConstructed ? childCount : 0;
    }
    /// <summary>
    ///     Moves from the current type to the next type. If current type is container or constructed
    ///     type (<strong>SEQUENCE</strong>, <strong>SEQUENCE OF</strong>, <strong>SET</strong>,
    ///     <strong>SET OF</strong>, <strong>OCTET STRING</strong> or <strong>context-specific</strong>),
    ///     <strong>MoveNext()</strong> method moves to the inner (wrapped) type which starts at the
    ///     container's payload position.
    ///     <para>If the current type is primitive type, <strong>MoveNext()</strong> method seeks over current
    ///     type to the next type.</para>
    /// </summary>
    /// <returns>
    ///     <strong>True</strong> if the current type is not the last in the data contained in
    ///     <strong>RawData</strong> property and there are no inner (wrapped) types, otherwise
    ///     <strong>False</strong>
    /// </returns>
    public Boolean MoveNext() {
        if (NextOffset == 0) {
            return false;
        }
        currentPosition = _offsetMap[NextOffset];
        decode(null, NextOffset);
        return true;
    }
    /// <summary>
    /// Moves from the current type to the next type in a tree and checks whether the tag number of next type
    /// matches one of specified in the <strong>expectedTags</strong> parameter. If current position is the last type
    /// in the data, or next type's tag doesn't match a list of accepted types, an exception is thrown. See
    /// exceptions for more details. If the method succeeds, it returns nothing.
    /// </summary>
    /// <param name="expectedTags">
    /// One or more ASN.1 types client expects after moving to next type in ASN.1 tree.
    /// </param>
    /// <exception cref="ArgumentNullException">
    /// <strong>expectedTags</strong> parameter is null;
    /// </exception>
    /// <exception cref="InvalidDataException">
    /// Current position of the reader is the last type in a file.
    /// </exception>
    /// <exception cref="Asn1InvalidTagException">
    /// Reader was able to move to next type, but its identifier doesn't match any accepted type specified in the
    /// <strong>expectedTags</strong> parameter.
    /// </exception>
    public void MoveNextAndExpectTags(params Byte[] expectedTags) {
        moveAndExpectTypes(MoveNext, expectedTags);
    }
    /// <summary>
    /// Moves from the current type to the next type in a tree and checks whether the tag number of next type
    /// matches one of specified in the <strong>expectedTags</strong> parameter. If current position is the last type
    /// in the data, or next type's tag doesn't match a list of accepted types, an exception is thrown. See
    /// exceptions for more details. If the method succeeds, it returns nothing.
    /// </summary>
    /// <param name="expectedTags">
    /// One or more ASN.1 types client expects after moving to next type in ASN.1 tree.
    /// </param>
    /// <exception cref="ArgumentNullException">
    /// <strong>expectedTags</strong> parameter is null;
    /// </exception>
    /// <exception cref="InvalidDataException">
    /// Current position of the reader is the last type in a file.
    /// </exception>
    /// <exception cref="Asn1InvalidTagException">
    /// Reader was able to move to next type, but its identifier doesn't match any accepted type specified in the
    /// <strong>expectedTags</strong> parameter.
    /// </exception>
    public void MoveNextAndExpectTags(params Asn1Type[] expectedTags) {
        moveAndExpectTypes(MoveNext, expectedTags.Select(x => (Byte)x).ToArray());
    }
    /// <summary>
    /// Moves over current type to the next type at the same level. If the current type is a
    /// container (or constructed type), the method skips entire container.
    /// </summary>
    /// <returns>
    /// <strong>True</strong> if the current type is not the last type at the current deepness level (or upper
    /// level), otherwise <strong>False</strong>.
    /// </returns>
    public Boolean MoveNextSibling() {
        if (NextSiblingOffset == 0) {
            return false;
        }
        currentPosition = _offsetMap[NextSiblingOffset];
        decode(null, NextSiblingOffset);
        return true;
    }
    /// <summary>
    /// Moves over current type to the next type at the same level and checks whether the tag number of next type
    /// matches one of specified in the <strong>expectedTags</strong> parameter. If current position is the last type
    /// in the current array, or next type's tag doesn't match a list of accepted types, an exception is thrown. See
    /// exceptions for more details. If the method succeeds, it returns nothing.
    /// </summary>
    /// <param name="expectedTags">
    /// One or more ASN.1 types client expects after moving to next type in ASN.1 tree.
    /// </param>
    /// <exception cref="ArgumentNullException">
    /// <strong>expectedTags</strong> parameter is null;
    /// </exception>
    /// <exception cref="InvalidDataException">
    /// Current position of the reader is the last type in a file.
    /// </exception>
    /// <exception cref="Asn1InvalidTagException">
    /// Reader was able to move to next type at same level, but its identifier doesn't match any accepted type
    /// specified in the <strong>expectedTags</strong> parameter.
    /// </exception>
    public void MoveNextSiblingAndExpectTags(params Byte[] expectedTags) {
        moveAndExpectTypes(MoveNextSibling, expectedTags);
    }
    /// <summary>
    /// Moves over current type to the next type at the same level and checks whether the tag number of next type
    /// matches one of specified in the <strong>expectedTags</strong> parameter. If current position is the last type
    /// in the current array, or next type's tag doesn't match a list of accepted types, an exception is thrown. See
    /// exceptions for more details. If the method succeeds, it returns nothing.
    /// </summary>
    /// <param name="expectedTags">
    /// One or more ASN.1 types client expects after moving to next type in ASN.1 tree.
    /// </param>
    /// <exception cref="ArgumentNullException">
    /// <strong>expectedTags</strong> parameter is null;
    /// </exception>
    /// <exception cref="InvalidDataException">
    /// Current position of the reader is the last type in a file.
    /// </exception>
    /// <exception cref="Asn1InvalidTagException">
    /// Reader was able to move to next type at same level, but its identifier doesn't match any accepted type
    /// specified in the <strong>expectedTags</strong> parameter.
    /// </exception>
    public void MoveNextSiblingAndExpectTags(params Asn1Type[] expectedTags) {
        moveAndExpectTypes(MoveNextSibling, expectedTags.Select(x => (Byte)x).ToArray());
    }
    /// <summary>
    /// Moves to a specified start offset.
    /// </summary>
    /// <param name="newPosition">ASN structure start position (offset).</param>
    /// <returns>
    /// <strong>True</strong> if specified offset is valid and pointer was successfully set to specified position,
    /// otherwise <strong>False</strong>.
    /// </returns>
    /// <remarks>
    /// Specified position validity is determined based on internal map and <see cref="BuildOffsetMap"/>
    /// method must be called prior to first call of this method. Subsequent <strong>BuildOffsetMap</strong>
    /// method calls are not necessary.
    /// </remarks>
    public Boolean Seek(Int32 newPosition) {
        if (!_offsetMap.TryGetValue(newPosition, out AsnInternalMap? value)) {
            return false;
        }
        currentPosition = value;
        decode(null, newPosition);

        return true;
    }

    /// <summary>
    /// Moves to the beginning of the file.
    /// </summary>
    public void Reset() {
        currentPosition = _offsetMap[0];
        decode(null, 0);
    }
    /// <summary>
    /// Gets the appropriate primitive tag object from <strong>Universal</strong> namespace, or <see cref="Asn1Universal"/> object.
    /// </summary>
    /// <returns>ASN.1 object that represents current tag.</returns>
    public Asn1Universal GetTagObject() {
        return Tag switch {
            (Byte)Asn1Type.BOOLEAN           => new Asn1Boolean(this),
            (Byte)Asn1Type.INTEGER           => new Asn1Integer(this),
            (Byte)Asn1Type.BIT_STRING        => new Asn1BitString(this),
            (Byte)Asn1Type.OCTET_STRING      => new Asn1OctetString(this),
            (Byte)Asn1Type.NULL              => new Asn1Null(this),
            (Byte)Asn1Type.OBJECT_IDENTIFIER => new Asn1ObjectIdentifier(this),
            (Byte)Asn1Type.RELATIVE_OID      => new Asn1RelativeOid(this),
            (Byte)Asn1Type.ENUMERATED        => new Asn1Enumerated(this),
            (Byte)Asn1Type.UTF8String        => new Asn1UTF8String(this),
            (Byte)Asn1Type.NumericString     => new Asn1NumericString(this),
            (Byte)Asn1Type.PrintableString   => new Asn1PrintableString(this),
            (Byte)Asn1Type.TeletexString     => new Asn1TeletexString(this),
            (Byte)Asn1Type.VideotexString    => new Asn1VideotexString(this),
            (Byte)Asn1Type.IA5String         => new Asn1IA5String(this),
            (Byte)Asn1Type.UTCTime           => new Asn1UtcTime(this),
            (Byte)Asn1Type.GeneralizedTime   => new Asn1GeneralizedTime(this),
            (Byte)Asn1Type.VisibleString     => new Asn1VisibleString(this),
            (Byte)Asn1Type.UniversalString   => new Asn1UniversalString(this),
            (Byte)Asn1Type.BMPString         => new Asn1BMPString(this),
            _                                => new Asn1AnyType(this)
        };
    }
    /// <summary>
    /// Returns a new instance of <see cref="Asn1Reader"/> that is sourced from the current tag.
    /// </summary>
    /// <returns>A new instance of <see cref="Asn1Reader"/>.</returns>
    public Asn1Reader GetReader() {
        return new Asn1Reader(GetTagRawDataAsMemory(), 0, true);
    }
    /// <summary>
    /// Recursively processes ASN tree and builds internal offset map.
    /// </summary>
    /// <returns>A number of processed ASN structures.</returns>
    /// <remarks>
    /// This method resets current parser position to zero.
    /// </remarks>
    public Int32 BuildOffsetMap() {
        Reset();
        do { } while (MoveNext());
        Reset();
        return _offsetMap.Count;
    }
    /// <summary>
    /// Gets the list of tags that can be represented in a primitive form only.
    /// </summary>
    /// <returns>Byte array.</returns>
    public static List<Byte> GetRestrictedTags() {
        return _excludedTags.ToList();
    }
    /// <summary>
    /// Gets the formatted tag name.
    /// </summary>
    /// <param name="tag">Tag numerical value.</param>
    /// <returns>Formatted tag name</returns>
    public static String GetTagName(Byte tag) {
        Int32 index = tag & (Byte)Asn1Type.TAG_MASK;
        if ((tag & (Byte)Asn1Class.PRIVATE) != 0) {
            switch (tag & (Byte)Asn1Class.PRIVATE) {
                case (Byte)Asn1Class.CONTEXT_SPECIFIC:
                    return $"CONTEXT_SPECIFIC [{index}]";
                case (Byte)Asn1Class.APPLICATION:
                    return $"APPLICATION [{index}]";
                case (Byte)Asn1Class.PRIVATE:
                    return $"PRIVATE [{index}]";
                case (Byte)Asn1Class.CONSTRUCTED:
                    return $"CONSTRUCTED [{index}]";
            }
        }
        return ((Asn1Type)index).ToString();
    }

    record AsnInternalMap(Int64 LevelStart, Int64 LevelEnd) {
        public Int64 LevelStart { get; } = LevelStart;
        public Int64 LevelEnd { get; } = LevelEnd;
    }
}