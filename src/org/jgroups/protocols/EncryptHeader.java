package org.jgroups.protocols;

import org.jgroups.Global;
import org.jgroups.Header;
import org.jgroups.util.Util;

import java.io.DataInput;
import java.io.DataOutput;
import java.util.function.Supplier;

/**
 * @author Bela Ban
 * @since  4.0
 */
public class EncryptHeader extends Header {
    public static final byte ENCRYPT            = 1;
    public static final byte SECRET_KEY_REQ     = 2;
    public static final byte SECRET_KEY_RSP     = 3;
    public static final byte NEW_KEYSERVER      = 4;
    public static final byte NEW_KEYSERVER_ACK  = 5;
    public static final byte PUB_KEY            = 6; // body of the message contains the mappings
    public static final byte INSTALL_SHARED_KEY = 7; // body of the message contains the encrypted shared keys

    protected byte   type;
    protected byte[] version;
    protected byte[] key; // public key on JOIN-REQ or encrypted group key on JOIN-RSP


    public EncryptHeader() {}


    public EncryptHeader(byte type, byte[] version) {
        this.type=type;
        this.version=version;
    }

    public byte                       type()        {return type;}
    public byte[]                     version()     {return version;}
    public short                      getMagicId()  {return 88;}
    public Supplier<? extends Header> create()      {return EncryptHeader::new;}
    public EncryptHeader              key(byte[] k) {this.key=k; return this;}
    public byte[]                     key()         {return key;}

    public void writeTo(DataOutput out) throws Exception {
        out.writeByte(type);
        Util.writeByteBuffer(version, 0, version != null? version.length : 0, out);
        Util.writeByteBuffer(key, 0, key != null? key.length : 0, out);
    }

    public void readFrom(DataInput in) throws Exception {
        type=in.readByte();
        version=Util.readByteBuffer(in);
        key=Util.readByteBuffer(in);
    }

    public String toString() {
        return String.format("%s [version=%s, key=%s]", typeToString(type),
                             (version != null? Util.byteArrayToHexString(version) : "null"),
                             (key != null? (key.length + " bytes") : "null"));
    }

    public int serializedSize() {return Global.BYTE_SIZE + Util.size(version) + Util.size(key);}

    protected static String typeToString(byte type) {
        switch(type) {
            case ENCRYPT:            return "ENCRYPT";
            case SECRET_KEY_REQ:     return "SECRET_KEY_REQ";
            case SECRET_KEY_RSP:     return "SECRET_KEY_RSP";
            case NEW_KEYSERVER:      return "NEW_KEYSERVER";
            case NEW_KEYSERVER_ACK:  return "NEW_KEYSERVER_ACK";
            case PUB_KEY:            return "PUB_KEY";
            case INSTALL_SHARED_KEY: return "INSTALL_SHARED_KEY";
            default:                 return "<unrecognized type " + type;
        }
    }
}
