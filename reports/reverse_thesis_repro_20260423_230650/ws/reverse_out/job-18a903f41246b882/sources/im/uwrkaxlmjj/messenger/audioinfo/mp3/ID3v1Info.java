package im.uwrkaxlmjj.messenger.audioinfo.mp3;

import im.uwrkaxlmjj.messenger.audioinfo.AudioInfo;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import kotlin.UByte;

/* JADX INFO: loaded from: classes2.dex */
public class ID3v1Info extends AudioInfo {
    /* JADX WARN: Removed duplicated region for block: B:11:0x001e  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static boolean isID3v1StartPosition(java.io.InputStream r2) throws java.io.IOException {
        /*
            r0 = 3
            r2.mark(r0)
            int r0 = r2.read()     // Catch: java.lang.Throwable -> L23
            r1 = 84
            if (r0 != r1) goto L1e
            int r0 = r2.read()     // Catch: java.lang.Throwable -> L23
            r1 = 65
            if (r0 != r1) goto L1e
            int r0 = r2.read()     // Catch: java.lang.Throwable -> L23
            r1 = 71
            if (r0 != r1) goto L1e
            r0 = 1
            goto L1f
        L1e:
            r0 = 0
        L1f:
            r2.reset()
            return r0
        L23:
            r0 = move-exception
            r2.reset()
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.audioinfo.mp3.ID3v1Info.isID3v1StartPosition(java.io.InputStream):boolean");
    }

    public ID3v1Info(InputStream input) throws IOException {
        if (isID3v1StartPosition(input)) {
            this.brand = "ID3";
            this.version = "1.0";
            byte[] bytes = readBytes(input, 128);
            this.title = extractString(bytes, 3, 30);
            this.artist = extractString(bytes, 33, 30);
            this.album = extractString(bytes, 63, 30);
            try {
                this.year = Short.parseShort(extractString(bytes, 93, 4));
            } catch (NumberFormatException e) {
                this.year = (short) 0;
            }
            this.comment = extractString(bytes, 97, 30);
            ID3v1Genre id3v1Genre = ID3v1Genre.getGenre(bytes[127]);
            if (id3v1Genre != null) {
                this.genre = id3v1Genre.getDescription();
            }
            if (bytes[125] == 0 && bytes[126] != 0) {
                this.version = "1.1";
                this.track = (short) (bytes[126] & UByte.MAX_VALUE);
            }
        }
    }

    byte[] readBytes(InputStream input, int len) throws IOException {
        int total = 0;
        byte[] bytes = new byte[len];
        while (total < len) {
            int current = input.read(bytes, total, len - total);
            if (current > 0) {
                total += current;
            } else {
                throw new EOFException();
            }
        }
        return bytes;
    }

    String extractString(byte[] bytes, int offset, int length) {
        try {
            String text = new String(bytes, offset, length, "ISO-8859-1");
            int zeroIndex = text.indexOf(0);
            return zeroIndex < 0 ? text : text.substring(0, zeroIndex);
        } catch (Exception e) {
            return "";
        }
    }
}
