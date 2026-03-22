package p005b.p310s.p311a;

import android.content.Context;
import android.graphics.Bitmap;
import android.os.Bundle;
import android.os.Handler;
import androidx.core.view.ViewCompat;
import java.io.ByteArrayOutputStream;
import java.util.Map;
import p005b.p199l.p266d.C2528j;
import p005b.p199l.p266d.C2530l;
import p005b.p199l.p266d.EnumC2523e;
import p005b.p310s.p311a.p312o.C2748d;

/* renamed from: b.s.a.k */
/* loaded from: classes2.dex */
public final class HandlerC2741k extends Handler {

    /* renamed from: a */
    public static final String f7493a = HandlerC2741k.class.getSimpleName();

    /* renamed from: b */
    public final Context f7494b;

    /* renamed from: c */
    public final C2748d f7495c;

    /* renamed from: d */
    public final HandlerC2738h f7496d;

    /* renamed from: e */
    public final C2528j f7497e;

    /* renamed from: f */
    public boolean f7498f = true;

    /* renamed from: g */
    public long f7499g;

    public HandlerC2741k(Context context, C2748d c2748d, HandlerC2738h handlerC2738h, Map<EnumC2523e, Object> map) {
        C2528j c2528j = new C2528j();
        this.f7497e = c2528j;
        c2528j.m2931c(map);
        this.f7494b = context;
        this.f7495c = c2748d;
        this.f7496d = handlerC2738h;
    }

    /* renamed from: b */
    public static void m3251b(C2530l c2530l, Bundle bundle) {
        int i2 = c2530l.f6838a / 2;
        int i3 = c2530l.f6839b / 2;
        int[] iArr = new int[i2 * i3];
        byte[] bArr = c2530l.f6844c;
        int i4 = (c2530l.f6848g * c2530l.f6845d) + c2530l.f6847f;
        for (int i5 = 0; i5 < i3; i5++) {
            int i6 = i5 * i2;
            for (int i7 = 0; i7 < i2; i7++) {
                iArr[i6 + i7] = ((bArr[(i7 << 1) + i4] & 255) * 65793) | ViewCompat.MEASURED_STATE_MASK;
            }
            i4 += c2530l.f6845d << 1;
        }
        int i8 = c2530l.f6838a / 2;
        Bitmap createBitmap = Bitmap.createBitmap(iArr, 0, i8, i8, c2530l.f6839b / 2, Bitmap.Config.ARGB_8888);
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        createBitmap.compress(Bitmap.CompressFormat.JPEG, 50, byteArrayOutputStream);
        bundle.putByteArray("barcode_bitmap", byteArrayOutputStream.toByteArray());
        bundle.putFloat("barcode_scaled_factor", i8 / c2530l.f6838a);
    }

    /* renamed from: a */
    public final C2530l m3252a(byte[] bArr, int i2, int i3, boolean z) {
        if (!z) {
            return this.f7495c.m3264a(bArr, i2, i3);
        }
        byte[] bArr2 = new byte[bArr.length];
        for (int i4 = 0; i4 < i3; i4++) {
            for (int i5 = 0; i5 < i2; i5++) {
                bArr2[(((i5 * i3) + i3) - i4) - 1] = bArr[(i4 * i2) + i5];
            }
        }
        return this.f7495c.m3264a(bArr2, i3, i2);
    }

    /* JADX WARN: Removed duplicated region for block: B:30:0x014e  */
    @Override // android.os.Handler
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void handleMessage(android.os.Message r13) {
        /*
            Method dump skipped, instructions count: 428
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p310s.p311a.HandlerC2741k.handleMessage(android.os.Message):void");
    }
}
