package com.bumptech.glide.load;

import androidx.annotation.NonNull;
import java.io.InputStream;
import java.nio.ByteBuffer;
import p005b.p143g.p144a.p147m.p150t.p151c0.InterfaceC1612b;

/* loaded from: classes.dex */
public interface ImageHeaderParser {

    public enum ImageType {
        GIF(true),
        JPEG(false),
        RAW(false),
        PNG_A(true),
        PNG(false),
        WEBP_A(true),
        WEBP(false),
        UNKNOWN(false);


        /* renamed from: c */
        public final boolean f8842c;

        ImageType(boolean z) {
            this.f8842c = z;
        }

        public boolean hasAlpha() {
            return this.f8842c;
        }
    }

    @NonNull
    /* renamed from: a */
    ImageType mo996a(@NonNull ByteBuffer byteBuffer);

    @NonNull
    /* renamed from: b */
    ImageType mo997b(@NonNull InputStream inputStream);

    /* renamed from: c */
    int mo998c(@NonNull InputStream inputStream, @NonNull InterfaceC1612b interfaceC1612b);
}
