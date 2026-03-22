package tv.danmaku.ijk.media.player.misc;

/* loaded from: classes3.dex */
public interface IAndroidIO {
    int close();

    int open(String str);

    int read(byte[] bArr, int i2);

    long seek(long j2, int i2);
}
