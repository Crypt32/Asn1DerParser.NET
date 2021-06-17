using System;
using System.Collections.Generic;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace SysadminsLV.Asn1Parser.Universal {
    /// <summary>
    /// Represents ASN.1 Object Identifier type.
    /// </summary>
    public sealed class Asn1ObjectIdentifier : UniversalTagBase {
        const Asn1Type TYPE = Asn1Type.OBJECT_IDENTIFIER;
        const Byte     TAG  = (Byte)TYPE;

        /// <summary>
        /// Initializes a new instance of the <strong>Asn1ObjectIdentifier</strong> class from an existing
        /// <see cref="Asn1Reader"/> class instance.
        /// </summary>
        /// <param name="asn"><see cref="Asn1Reader"/> object in the position that represents object identifier.</param>
        /// <exception cref="Asn1InvalidTagException">
        /// The current state of <strong>ASN1</strong> object is not object identifier.
        /// </exception>
        /// 
        public Asn1ObjectIdentifier(Asn1Reader asn) : base(asn) {
            if (asn.Tag != TAG) {
                throw new Asn1InvalidTagException(String.Format(InvalidType, TYPE.ToString()));
            }
            Value = new Oid(decode(asn));
        }
        /// <summary>
        /// Initializes a new instance of the <strong>Asn1ObjectIdentifier</strong> class from a byte array
        /// that represents encoded object identifier.
        /// </summary>
        /// <param name="rawData">Byte array that represents encoded object identifier.</param>
        public Asn1ObjectIdentifier(Byte[] rawData) : this(new Asn1Reader(rawData)) { }
        /// <summary>
        /// Initializes a new instance of the <strong>Asn1ObjectIdentifier</strong> class from a string
        /// that represents object identifier value.
        /// </summary>
        /// <param name="oid">String represents object identifier value.</param>
        /// <exception cref="InvalidDataException">The string is not valid object identifier.</exception>
        /// <exception cref="OverflowException">The string is too large.</exception>
        /// <remarks>Maximum object identifier string is 8kb.</remarks>
        public Asn1ObjectIdentifier(String oid) : this(new Oid(oid)) { }
        /// <summary>
        /// Initializes a new instance of the <strong>Asn1ObjectIdentifier</strong> class from an OID object.
        /// </summary>
        /// <param name="oid">Object identifier (OID).</param>
        /// <exception cref="ArgumentNullException"><strong>oid</strong> parameter is null.</exception>
        /// <exception cref="InvalidDataException">The string is not valid object identifier.</exception>
        /// <exception cref="OverflowException">The string is too large.</exception>
        public Asn1ObjectIdentifier(Oid oid) {
            if (oid == null) {
                throw new ArgumentNullException(nameof(oid));
            }
            m_encode(oid);
        }

        /// <summary>
        /// Gets value associated with the current object.
        /// </summary>
        public Oid Value { get; private set; }

        void m_encode(Oid oid) {
            if (String.IsNullOrWhiteSpace(oid.Value)) {
                Initialize(new Asn1Reader(new Byte[] { TAG, 0 }));
                Value = new Oid();
                return;
            }
            if (oid.Value.Length > 8096) { throw new OverflowException("Oid string is longer than 8kb"); }
            if (!validateOidString(oid.Value, out List<BigInteger> tokens)) {
                throw new InvalidDataException(String.Format(InvalidType, TYPE.ToString()));
            }
            Value = oid;
            Initialize(new Asn1Reader(Asn1Utils.Encode(encode(tokens), TAG)));
        }

        static Byte[] encode(IList<BigInteger> tokens) {
            List<Byte> rawOid = new List<Byte>();
            for (Int32 token = 0; token < tokens.Count; token++) {
                // first two arcs are encoded in a single byte
                switch (token) {
                    case 0:
                        rawOid.Add((Byte)(40 * tokens[token] + tokens[token + 1]));
                        continue;
                    case 1:
                        continue;
                }
                Int16 bitLength = 0;
                BigInteger temp = tokens[token];
                // calculate how many bits are occupied by the current integer value
                do {
                    temp = (BigInteger)Math.Floor((Double)temp / 2);
                    bitLength++;
                } while (temp > 0);
                // calculate how many additional bytes are required and encode each integer in a 7 bit.
                // 8th bit of the integer is shifted to the left and 8th bit is set to 1 to indicate that
                // additional bytes are related to the current OID arc. Details:
                // http://msdn.microsoft.com/en-us/library/bb540809(v=vs.85).aspx
                // loop may not execute if arc value is less than 128.
                for (Int32 index = (bitLength - 1) / 7; index > 0; index--) {
                    rawOid.Add((Byte)(0x80 | ((tokens[token] >> (index * 7)) & 0x7f)));
                }
                rawOid.Add((Byte)(tokens[token] & 0x7f));
            }
            return rawOid.ToArray();
        }
        static String decode(Asn1Reader asn) {
            StringBuilder SB = new StringBuilder();
            Int32 token = 0;
            for (Int32 i = 0; i < asn.PayloadLength; i++) {
                if (token == 0) {
                    SB.Append(asn[asn.Offset + i] / 40);
                    SB.Append("." + asn[asn.Offset + i] % 40);
                    token++;
                    continue;
                }
                BigInteger value = 0;
                Boolean proceed;
                do {
                    value <<= 7;
                    value += asn[asn.Offset + i] & 0x7f;
                    proceed = (asn[asn.Offset + i] & 0x80) > 0;
                    if (proceed) {
                        token++;
                        i++;
                    }
                } while (proceed);
                SB.Append("." + value);
                token++;
            }
            return SB.ToString();
        }
        static Boolean validateOidString(String oid, out List<BigInteger> tokens) {
            String[] strTokens = oid.Split('.');
            if (strTokens.Length < 3) {
                tokens = null;
                return false;
            }
            tokens = new List<BigInteger>();
            for (Int32 index = 0; index < strTokens.Length; index++) {
                try {
                    BigInteger value = BigInteger.Parse(strTokens[index]);
                    if (index == 0 && value > 2 || index == 1 && value > 39) {
                        return false;
                    }
                    tokens.Add(value);
                } catch {
                    tokens = null;
                    return false;
                }
            }
            return true;
        }

        /// <inheritdoc/>
        public override String GetDisplayValue() {
            return String.IsNullOrEmpty(Value.FriendlyName)
                ? Value.Value
                : Value.FriendlyName + " (" + Value.Value + ")";
        }
    }
}
