package im.uwrkaxlmjj.messenger.audioinfo.mp3;

import im.uwrkaxlmjj.messenger.audioinfo.util.PositionInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;

/* JADX INFO: loaded from: classes2.dex */
public class MP3Input extends PositionInputStream {
    public MP3Input(InputStream delegate) throws IOException {
        super(delegate);
    }

    public MP3Input(InputStream delegate, long position) {
        super(delegate, position);
    }

    public final void readFully(byte[] b, int off, int len) throws IOException {
        int total = 0;
        while (total < len) {
            int current = read(b, off + total, len - total);
            if (current > 0) {
                total += current;
            } else {
                throw new EOFException();
            }
        }
    }

    public void skipFully(long len) throws IOException {
        long total = 0;
        while (total < len) {
            long current = skip(len - total);
            if (current > 0) {
                total += current;
            } else {
                throw new EOFException();
            }
        }
    }

    public String toString() {
        return "mp3[pos=" + getPosition() + "]";
    }
}
