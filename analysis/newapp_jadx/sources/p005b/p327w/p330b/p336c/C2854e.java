package p005b.p327w.p330b.p336c;

import android.util.Base64;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt__StringsJVMKt;
import kotlin.text.StringsKt__StringsKt;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p143g.p144a.EnumC1556f;
import p005b.p143g.p144a.p147m.EnumC1569a;
import p005b.p143g.p144a.p147m.p148s.InterfaceC1590d;
import p458k.AbstractC4393m0;
import p458k.C4375d0;
import p458k.C4379f0;
import p458k.C4381g0;
import p458k.C4389k0;
import p458k.InterfaceC4378f;

/* renamed from: b.w.b.c.e */
/* loaded from: classes2.dex */
public final class C2854e implements InterfaceC1590d<ByteBuffer> {

    /* renamed from: c */
    @NotNull
    public final String f7778c;

    /* renamed from: e */
    @Nullable
    public InterfaceC4378f f7779e;

    public C2854e(@NotNull String model) {
        Intrinsics.checkNotNullParameter(model, "model");
        this.f7778c = model;
    }

    @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d
    @NotNull
    /* renamed from: a */
    public Class<ByteBuffer> mo832a() {
        return ByteBuffer.class;
    }

    @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d
    /* renamed from: b */
    public void mo835b() {
    }

    @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d
    public void cancel() {
        InterfaceC4378f interfaceC4378f = this.f7779e;
        if (interfaceC4378f != null) {
            Intrinsics.checkNotNull(interfaceC4378f);
            if (interfaceC4378f.mo4962b()) {
                return;
            }
            InterfaceC4378f interfaceC4378f2 = this.f7779e;
            Intrinsics.checkNotNull(interfaceC4378f2);
            interfaceC4378f2.cancel();
        }
    }

    @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d
    /* renamed from: d */
    public void mo837d(@NotNull EnumC1556f priority, @NotNull InterfaceC1590d.a<? super ByteBuffer> callback) {
        String str;
        Intrinsics.checkNotNullParameter(priority, "priority");
        Intrinsics.checkNotNullParameter(callback, "callback");
        try {
            C4381g0.a aVar = new C4381g0.a();
            aVar.m4978h(this.f7778c);
            C2853d c2853d = C2853d.f7770a;
            aVar.m4971a("referer", C2853d.f7771b);
            InterfaceC4378f mo4955a = new C4375d0(new C4375d0.a()).mo4955a(aVar.m4972b());
            this.f7779e = mo4955a;
            Intrinsics.checkNotNull(mo4955a);
            C4389k0 m4965a = ((C4379f0) mo4955a).m4965a();
            if (m4965a.f11488h == 200) {
                if (StringsKt__StringsKt.contains$default((CharSequence) this.f7778c, (CharSequence) ".safe.txt?ext=", false, 2, (Object) null)) {
                    AbstractC4393m0 abstractC4393m0 = m4965a.f11491k;
                    Intrinsics.checkNotNull(abstractC4393m0);
                    String base64Str = abstractC4393m0.m5008o();
                    Intrinsics.checkNotNullParameter(base64Str, "base64Str");
                    if (!StringsKt__StringsJVMKt.isBlank(base64Str)) {
                        str = base64Str.substring(StringsKt__StringsKt.indexOf$default((CharSequence) base64Str, ',', 0, false, 6, (Object) null) + 1);
                        Intrinsics.checkNotNullExpressionValue(str, "this as java.lang.String).substring(startIndex)");
                    } else {
                        str = "";
                    }
                    String str2 = str;
                    for (Map.Entry<String, String> entry : C2853d.f7772c.entrySet()) {
                        str2 = StringsKt__StringsJVMKt.replace$default(str2, entry.getValue(), entry.getKey(), false, 4, (Object) null);
                    }
                    ByteBuffer wrap = ByteBuffer.wrap(Base64.decode(str2, 0));
                    Intrinsics.checkNotNullExpressionValue(wrap, "wrap(imageByteArray)");
                    callback.mo840e(wrap);
                    return;
                }
                if (!StringsKt__StringsKt.contains$default((CharSequence) this.f7778c, (CharSequence) ".enc", false, 2, (Object) null)) {
                    if (StringsKt__StringsKt.contains$default((CharSequence) this.f7778c, (CharSequence) ".bnc", false, 2, (Object) null)) {
                        AbstractC4393m0 abstractC4393m02 = m4965a.f11491k;
                        Intrinsics.checkNotNull(abstractC4393m02);
                        callback.mo840e(ByteBuffer.wrap(c2853d.m3299a(abstractC4393m02.m5007b(), "525202f9149e061d")));
                        return;
                    } else {
                        AbstractC4393m0 abstractC4393m03 = m4965a.f11491k;
                        Intrinsics.checkNotNull(abstractC4393m03);
                        callback.mo840e(ByteBuffer.wrap(abstractC4393m03.m5007b()));
                        return;
                    }
                }
                AbstractC4393m0 abstractC4393m04 = m4965a.f11491k;
                Intrinsics.checkNotNull(abstractC4393m04);
                String replace$default = StringsKt__StringsJVMKt.replace$default(abstractC4393m04.m5008o(), " ", "", false, 4, (Object) null);
                HashMap<String, String> hashMap = C2853d.f7773d;
                String str3 = replace$default;
                for (String key : hashMap.keySet()) {
                    String str4 = hashMap.get(key);
                    Intrinsics.checkNotNull(str4);
                    Intrinsics.checkNotNullExpressionValue(key, "key");
                    str3 = StringsKt__StringsJVMKt.replace$default(str3, str4, key, false, 4, (Object) null);
                }
                int length = str3.length();
                if (length % 2 != 0) {
                    str3 = "0" + str3;
                    length++;
                }
                int i2 = length / 2;
                byte[] bArr = new byte[i2];
                for (int i3 = 0; i3 < i2; i3++) {
                    int i4 = i3 * 2;
                    bArr[i3] = (byte) Integer.parseInt(str3.substring(i4, i4 + 2), 16);
                }
                callback.mo840e(ByteBuffer.wrap(bArr));
            }
        } catch (Exception e2) {
            e2.printStackTrace();
            callback.mo839c(e2);
            String str5 = "loadData: " + this.f7778c + "---" + e2;
        }
    }

    @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d
    @NotNull
    public EnumC1569a getDataSource() {
        return EnumC1569a.REMOTE;
    }
}
