package im.uwrkaxlmjj.messenger.voip;

import java.nio.ByteBuffer;

/* JADX INFO: loaded from: classes2.dex */
public class Resampler {
    public static native int convert44to48(ByteBuffer byteBuffer, ByteBuffer byteBuffer2);

    public static native int convert48to44(ByteBuffer byteBuffer, ByteBuffer byteBuffer2);
}
