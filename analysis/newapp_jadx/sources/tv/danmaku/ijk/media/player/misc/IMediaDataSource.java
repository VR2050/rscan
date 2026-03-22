package tv.danmaku.ijk.media.player.misc;

/* loaded from: classes3.dex */
public interface IMediaDataSource {
    void close();

    long getSize();

    int readAt(long j2, byte[] bArr, int i2, int i3);
}
