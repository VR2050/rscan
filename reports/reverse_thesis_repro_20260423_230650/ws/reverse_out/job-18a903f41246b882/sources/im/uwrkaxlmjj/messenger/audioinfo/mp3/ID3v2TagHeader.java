package im.uwrkaxlmjj.messenger.audioinfo.mp3;

import im.uwrkaxlmjj.messenger.audioinfo.util.PositionInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import kotlin.jvm.internal.ByteCompanionObject;

/* JADX INFO: loaded from: classes2.dex */
public class ID3v2TagHeader {
    private boolean compression;
    private int footerSize;
    private int headerSize;
    private int paddingSize;
    private int revision;
    private int totalTagSize;
    private boolean unsynchronization;
    private int version;

    public ID3v2TagHeader(InputStream input) throws ID3v2Exception, IOException {
        this(new PositionInputStream(input));
    }

    ID3v2TagHeader(PositionInputStream input) throws ID3v2Exception, IOException {
        this.version = 0;
        this.revision = 0;
        this.headerSize = 0;
        this.totalTagSize = 0;
        this.paddingSize = 0;
        this.footerSize = 0;
        long startPosition = input.getPosition();
        ID3v2DataInput data = new ID3v2DataInput(input);
        String id = new String(data.readFully(3), "ISO-8859-1");
        if (!"ID3".equals(id)) {
            throw new ID3v2Exception("Invalid ID3 identifier: " + id);
        }
        byte b = data.readByte();
        this.version = b;
        if (b != 2 && b != 3 && b != 4) {
            throw new ID3v2Exception("Unsupported ID3v2 version: " + this.version);
        }
        this.revision = data.readByte();
        byte flags = data.readByte();
        this.totalTagSize = data.readSyncsafeInt() + 10;
        if (this.version == 2) {
            this.unsynchronization = (flags & ByteCompanionObject.MIN_VALUE) != 0;
            this.compression = (flags & 64) != 0;
        } else {
            this.unsynchronization = (flags & ByteCompanionObject.MIN_VALUE) != 0;
            if ((flags & 64) != 0) {
                if (this.version == 3) {
                    int extendedHeaderSize = data.readInt();
                    data.readByte();
                    data.readByte();
                    this.paddingSize = data.readInt();
                    data.skipFully(extendedHeaderSize - 6);
                } else {
                    int extendedHeaderSize2 = data.readSyncsafeInt();
                    data.skipFully(extendedHeaderSize2 - 4);
                }
            }
            int extendedHeaderSize3 = this.version;
            if (extendedHeaderSize3 >= 4 && (flags & 16) != 0) {
                this.footerSize = 10;
                this.totalTagSize += 10;
            }
        }
        this.headerSize = (int) (input.getPosition() - startPosition);
    }

    public ID3v2TagBody tagBody(InputStream input) throws ID3v2Exception, IOException {
        if (this.compression) {
            throw new ID3v2Exception("Tag compression is not supported");
        }
        if (this.version < 4 && this.unsynchronization) {
            byte[] bytes = new ID3v2DataInput(input).readFully(this.totalTagSize - this.headerSize);
            int length = bytes.length;
            boolean ff = false;
            int len = 0;
            for (int i = 0; i < length; i++) {
                byte b = bytes[i];
                if (!ff || b != 0) {
                    bytes[len] = b;
                    len++;
                }
                ff = b == -1;
            }
            return new ID3v2TagBody(new ByteArrayInputStream(bytes, 0, len), this.headerSize, len, this);
        }
        int i2 = this.headerSize;
        return new ID3v2TagBody(input, i2, (this.totalTagSize - i2) - this.footerSize, this);
    }

    public int getVersion() {
        return this.version;
    }

    public int getRevision() {
        return this.revision;
    }

    public int getTotalTagSize() {
        return this.totalTagSize;
    }

    public boolean isUnsynchronization() {
        return this.unsynchronization;
    }

    public boolean isCompression() {
        return this.compression;
    }

    public int getHeaderSize() {
        return this.headerSize;
    }

    public int getFooterSize() {
        return this.footerSize;
    }

    public int getPaddingSize() {
        return this.paddingSize;
    }

    public String toString() {
        return String.format("%s[version=%s, totalTagSize=%d]", getClass().getSimpleName(), Integer.valueOf(this.version), Integer.valueOf(this.totalTagSize));
    }
}
