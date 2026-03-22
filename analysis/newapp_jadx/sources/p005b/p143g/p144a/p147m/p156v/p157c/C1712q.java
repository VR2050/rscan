package p005b.p143g.p144a.p147m.p156v.p157c;

import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;
import androidx.exifinterface.media.ExifInterface;
import com.bumptech.glide.load.ImageHeaderParser;
import java.io.InputStream;
import java.nio.ByteBuffer;
import p005b.p143g.p144a.p147m.p150t.p151c0.InterfaceC1612b;

@RequiresApi(27)
/* renamed from: b.g.a.m.v.c.q */
/* loaded from: classes.dex */
public final class C1712q implements ImageHeaderParser {
    @Override // com.bumptech.glide.load.ImageHeaderParser
    @NonNull
    /* renamed from: a */
    public ImageHeaderParser.ImageType mo996a(@NonNull ByteBuffer byteBuffer) {
        return ImageHeaderParser.ImageType.UNKNOWN;
    }

    @Override // com.bumptech.glide.load.ImageHeaderParser
    @NonNull
    /* renamed from: b */
    public ImageHeaderParser.ImageType mo997b(@NonNull InputStream inputStream) {
        return ImageHeaderParser.ImageType.UNKNOWN;
    }

    @Override // com.bumptech.glide.load.ImageHeaderParser
    /* renamed from: c */
    public int mo998c(@NonNull InputStream inputStream, @NonNull InterfaceC1612b interfaceC1612b) {
        int attributeInt = new ExifInterface(inputStream).getAttributeInt(ExifInterface.TAG_ORIENTATION, 1);
        if (attributeInt == 0) {
            return -1;
        }
        return attributeInt;
    }
}
